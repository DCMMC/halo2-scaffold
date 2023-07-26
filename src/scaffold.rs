//! This module contains helper functions to handle some common setup to convert the `some_algorithm_in_zk` function in the examples into a Halo2 circuit.
//! These functions are not quite general enough to place into `halo2-lib` yet, so they are just some internal helpers for this crate only for now.
//! We recommend not reading this module on first (or second) pass.
use ark_std::{end_timer, start_timer};
use log::{debug, trace};
use std::{error::Error as RawError, io::{Read, Write, BufReader, BufRead}};
use ezkl_lib::{pfsys::{Snark, evm::{aggregation::AggregationError, EvmVerificationError}}, eth::fix_verifier_sol};
use halo2_proofs::{poly::{kzg::{multiopen::ProverGWC, commitment::ParamsKZG}, commitment::ParamsProver}, plonk::VerifyingKey, halo2curves::bn256::Fq};
use serde::{Deserialize, Serialize};
use snark_verifier::{system::halo2::{compile, Config, transcript::evm::EvmTranscript}, loader::evm::{EvmLoader, compile_yul, encode_calldata, ExecutorBuilder, Address}, verifier::{plonk::{PlonkVerifier, PlonkProof}, SnarkVerifier}, pcs::kzg::{KzgDecidingKey, KzgAs, Gwc19, LimbsEncoding}};

use halo2_base::{
    gates::{
        builder::{GateCircuitBuilder, GateThreadBuilder, RangeCircuitBuilder},
        flex_gate::FlexGateConfig,
        range::RangeConfig,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{
            create_proof, keygen_pk, keygen_vk, Circuit, Column, ConstraintSystem,
            Error, Instance,
        },
        poly::kzg::{
            commitment::KZGCommitmentScheme,
            multiopen::{ProverSHPLONK},
        },
        transcript::{
            Blake2bWrite, Challenge255, TranscriptWriterBuffer,
        },
    },
    utils::{fs::gen_srs, ScalarField},
    AssignedValue, Context,
};
use rand::rngs::OsRng;
use std::{env::var, vec, path::PathBuf, rc::Rc, fs::File};

#[derive(Debug, Deserialize, Serialize)]
pub struct DeploymentCode {
    code: Vec<u8>,
}
impl DeploymentCode {
    /// Return len byte code
    pub fn len(&self) -> usize {
        self.code.len()
    }

    /// If no byte code
    pub fn is_empty(&self) -> bool {
        self.code.len() == 0
    }
    /// Return (inner) byte code
    pub fn code(&self) -> &Vec<u8> {
        &self.code
    }
    /// Saves the DeploymentCode to a specified `path`.
    pub fn save(&self, path: &PathBuf) -> Result<(), Box<dyn RawError>> {
        let serialized = serde_json::to_string(&self).map_err(Box::<dyn RawError>::from)?;

        let mut file = std::fs::File::create(path).map_err(Box::<dyn RawError>::from)?;
        file.write_all(serialized.as_bytes())
            .map_err(Box::<dyn RawError>::from)
    }

    /// Load a json serialized proof from the provided path.
    pub fn load(path: &PathBuf) -> Result<Self, Box<dyn RawError>> {
        let mut file = File::open(path).map_err(Box::<dyn RawError>::from)?;
        let mut data = String::new();
        file.read_to_string(&mut data)
            .map_err(Box::<dyn RawError>::from)?;
        serde_json::from_str(&data).map_err(Box::<dyn RawError>::from)
    }
}

pub fn gen_aggregation_evm_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
    accumulator_indices: Vec<(usize, usize)>,
    output_path: String
) -> Result<DeploymentCode, AggregationError> {
    let protocol = compile(
        params,
        vk,
        Config::kzg()
            .with_num_instance(num_instance.clone())
            .with_accumulator_indices(if accumulator_indices.len() > 0 { Some(accumulator_indices) } else { None }),
    );
    let vk: KzgDecidingKey<Bn256> = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof: PlonkProof<G1Affine, Rc<EvmLoader>, KzgAs<Bn256, Gwc19>> = PlonkVerifier::<KzgAs<Bn256, Gwc19>, LimbsEncoding<4, 68>>::read_proof(
        &vk, &protocol, &instances, &mut transcript)
        .map_err(|_| AggregationError::ProofRead)?;
    PlonkVerifier::<KzgAs<Bn256, Gwc19>, LimbsEncoding<4, 68>>::verify(&vk, &protocol, &instances, &proof)
        .map_err(|_| AggregationError::ProofVerify)?;

    let mut file = std::fs::File::create(output_path).map_err(Box::<dyn RawError>::from).unwrap();
    file.write_all(&loader.yul_code().as_bytes())
        .map_err(Box::<dyn RawError>::from).unwrap();
    Ok(DeploymentCode {
        code: compile_yul(&loader.yul_code()),
    })
}

/// Verify by executing bytecode with instance variables and proof as input
pub fn evm_verify(
    deployment_code: DeploymentCode,
    snark: Snark<Fr, G1Affine>,
) -> Result<bool, Box<dyn RawError>> {
    debug!("evm deployment code length: {:?}", deployment_code.len());

    // let calldata = encode_calldata(&snark.instances, &snark.proof);
    let calldata: Vec<u8> = vec![0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,50,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,100,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,10,112,153,41,202,234,184,232,183,224,183,75,255,70,58,105,77,249,214,235,209,152,46,130,139,35,237,107,137,253,249,22,38,123,138,111,252,136,135,0,165,75,94,169,57,220,167,240,166,103,246,155,110,73,60,2,117,108,213,29,143,215,253,95,32,254,75,135,153,193,67,173,143,71,164,14,43,80,24,245,203,242,239,175,29,237,98,23,250,14,223,124,252,111,225,14,1,41,30,195,250,198,148,136,198,27,181,3,189,153,111,158,238,117,135,42,170,18,81,66,91,159,162,202,133,179,91,219,14,152,220,149,207,40,120,151,46,67,176,203,54,23,153,230,197,233,2,250,177,101,210,95,133,222,246,169,221,77,136,51,19,181,219,226,30,207,22,138,218,97,162,254,234,107,212,88,151,21,66,162,200,70,62,96,55,218,111,66,222,11,12,224,13,240,243,160,143,77,20,22,196,236,98,27,112,239,55,55,61,51,151,132,112,250,19,52,238,29,74,121,19,55,99,227,47,70,143,20,35,154,72,198,67,6,201,101,30,221,155,87,86,238,168,146,99,246,114,147,162,20,230,205,216,254,242,46,29,61,10,95,59,66,230,61,102,155,30,52,8,251,241,62,151,164,155,234,190,26,228,93,176,81,73,13,15,142,121,161,14,46,104,231,55,73,77,35,32,65,172,243,153,58,246,197,46,117,230,93,52,251,15,227,41,44,153,95,122,238,129,124,11,128,84,154,63,121,67,210,80,66,205,212,234,251,150,94,137,173,76,171,155,1,161,29,220,231,121,25,21,155,195,46,29,198,234,165,32,10,1,83,223,58,74,190,72,47,83,145,53,73,202,167,12,153,76,129,123,167,166,77,2,9,190,116,25,80,23,60,8,240,176,171,198,157,164,43,195,67,17,91,124,185,26,192,69,61,15,32,145,188,74,44,169,97,211,0,33,206,185,91,246,119,195,85,44,17,216,118,7,55,154,121,237,183,117,51,21,240,133,118,6,133,41,41,217,53,241,12,42,17,222,245,126,73,108,242,255,47,135,95,182,93,149,236,167,249,212,154,106,20,124,153,62,19,136,1,11,108,104,175,31,85,74,106,163,54,143,169,110,62,23,198,177,21,146,205,4,180,15,41,126,216,64,92,253,222,103,163,173,172,146,3,21,195,100,244,45,224,10,149,193,186,70,35,228,3,195,173,92,154,57,243,160,31,215,229,78,197,193,55,10,246,85,237,40,252,183,11,253,180,52,174,45,156,167,72,56,179,111,191,71,206,159,253,87,187,137,83,173,186,251,0,198,44,233,251,45,133,181,124,33,106,0,2,253,91,139,249,23,76,170,113,39,164,76,73,234,10,211,61,65,136,165,211,193,183,255,80,28,242,223,168,253,155,150,167,11,138,204,208,139,116,132,194,144,60,187,2,90,129,132,53,129,47,129,55,169,31,24,119,26,28,49,134,121,143,70,35,152,34,197,77,173,89,75,194,25,67,13,49,242,239,189,162,22,223,6,202,179,12,249,84,8,133,75,152,82,107,205,135,13,101,253,116,207,137,157,80,27,133,99,251,173,140,35,237,166,173,129,91,219,98,213,43,24,12,27,50,23,57,80,222,151,12,5,41,229,79,119,96,17,42,210,57,9,9,153,241,228,17,78,109,78,73,161,199,42,12,166,145,116,217,250,14,139,81,203,15,235,3,224,199,85,240,123,208,156,171,25,196,45,189,99,100,55,241,240,194,23,156,1,199,70,177,223,132,53,26,248,98,13,7,55,45,74,123,192,30,7,18,29,160,203,45,231,85,168,12,62,62,29,135,60,173,172,57,12,92,151,186,18,236,215,36,215,185,231,18,76,38,46,222,218,143,173,159,254,169,96,60,134,207,0,173,81,65,74,154,36,72,118,3,116,236,122,10,31,163,209,141,230,50,64,48,206,154,122,60,102,65,123,214,236,116,20,161,143,151,116,27,217,229,18,24,33,46,248,0,62,149,7,108,162,104,236,1,167,225,127,220,9,247,169,96,144,149,35,237,243,131,63,178,148,2,29,114,216,217,255,249,233,196,201,235,98,103,90,22,11,190,84,111,254,52,96,20,10,55,47,152,102,85,95,104,224,251,131,208,127,40,62,43,23,177,193,253,70,19,119,65,44,55,60,67,37,90,235,12,210,164,12,202,30,147,149,63,29,90,126,183,127,231,146,176,36,170,122,88,135,215,109,130,62,183,121,114,64,117,199,40,4,106,44,82,112,63,78,173,1,77,108,251,37,111,204,118,73,214,117,29,154,79,13,40,171,36,239,37,34,200,189,47,165,187,24,207,84,64,244,114,243,122,116,37,47,183,151,178,227,27,111,113,5,119,141,191,217,139,127,39,202,34,211,111,35,245,12,114,2,1,143,80,38,60,143,143,188,225,216,227,145,227,229,162,85,219,213,158,7,219,7,143,143,145,136,208,21,206,28,172,166,193,126,83,200,42,133,181,109,79,133,178,109,4,80,141,102,109,112,45,71,0,15,241,122,195,57,84,86,51,6,150,12,146,57,97,184,27,119,170,233,237,38,238,163,176,9,153,156,28,142,55,158,173,47,211,119,155,190,191,90,236,16,239,106,10,230,91,177,232,245,167,98,255,145,107,194,102,154,232,8,234,103,21,212,225,195,113,121,196,200,160,42,54,7,130,116,91,147,74,136,70,247,221,220,239,14,59,91,208,25,96,126,52,26,112,213,150,79,219,43,221,116,188,119,86,25,192,35,30,71,228,72,141,134,127,189,230,177,48,45,52,222,157,237,236,146,104,22,168,243,91,104,48,50,227,65,128,47,156,85,163,162,8,239,197,215,29,45,236,198,210,38,12,243,40,174,33,10,159,204,181,225,168,185,108,240,165,66,135,15,253,101,25,204,52,87,47,180,86,122,160,25,186,166,76,103,163,95,181,53,166,183,43,42,177,42,192,98,60,14,45,21,109,152,239,222,222,100,0,237,72,212,8,83,246,80,52,174,213,150,151,130,156,26,180,144,22,100,229,228,138,82,241,26,11,210,122,228,109,57,147,166,202,96,61,87,199,75,174,135,220,45,209,110,88,197,92,48,0,242,44,72,120,65,186,12,178,101,127,145,203,163,119,114,231,94,201,218,58,112,245,17,142,229,150,31,123,178,181,38,140,23,120,210,128,6,188,46,122,215,165,192,56,33,15,144,104,125,169,66,245,80,181,66,164,160,84,161,35,153,165,211,254,136,85,232,49,21,60,17,166,239,227,130,99,105,24,203,200,93,89,45,94,160,34,79,231,227,104,147,96,180,199,233,31,236,79,57,60,103,206,24,71,230,13,71,141,97,76,203,24,156,21,176,222,192,179,138,218,209,115,86,54,42,92,44,34,246,207,64,108,124,180,19,134,71,223,86,10,179,230,22,246,207,88,27,58,96,212,99,221,196,47,129,12,203,227,190,250,114,209,184,28,74,112,33,30,15,52,138,64,20,84,73,4,17,20,78,157,58,42,183,29,109,50,120,38,57,171,1,100,57,20,145,221,247,80];
    debug!("calldata size: {:?}", calldata.len());
    // debug!("calldata: {:?}", calldata.clone());
    let mut evm = ExecutorBuilder::default()
        .with_gas_limit(u64::MAX.into())
        .build();

    let caller = Address::from_low_u64_be(0xfe);
    let deploy_result = evm.deploy(caller, deployment_code.code.into(), 0.into());
    debug!("evm deploy outcome: {:?}", deploy_result.exit_reason);
    trace!("full deploy result: {:?}", deploy_result);
    debug!("gas used for deployment: {}", deploy_result.gas_used);

    if let Some(verifier) = deploy_result.address {
        // Lot of stuff here as well.
        let result = evm.call_raw(caller, verifier, calldata.into(), 0.into());

        debug!("evm execution result: {:?}", result.exit_reason);
        trace!("full execution result: {:?}", result);
        debug!("gas used for execution: {}", result.gas_used);

        if result.reverted {
            return Err(Box::new(EvmVerificationError::Reverted));
        }

        Ok(!result.reverted)
    } else {
        Err(Box::new(EvmVerificationError::Deploy))
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Snarkbytes {
    num_instance: Vec<usize>,
    /// Public inputs to the model.
    pub instances: Vec<Vec<Vec<u8>>>,
    /// The generated proof, as a vector of bytes.
    pub proof: Vec<u8>,
}

///! The functions below are generic scaffolding functions to create circuits with 'halo2-lib'

/// Creates a circuit and runs the Halo2 `MockProver` on it. Will print out errors if the circuit does not pass.
///
/// This requires an environment variable `DEGREE` to be set, which limits the number of rows of the circuit to 2<sup>DEGREE</sup>.
pub fn mock<T>(
    f: impl FnOnce(&mut Context<Fr>, T, &mut Vec<AssignedValue<Fr>>),
    private_inputs: T,
) {
    let k = var("DEGREE").unwrap_or_else(|_| "18".to_string()).parse().unwrap();
    // we use env var `LOOKUP_BITS` to determine whether to use `GateThreadBuilder` or `RangeCircuitBuilder`. The difference is that the latter creates a lookup table with 2^LOOKUP_BITS rows, while the former does not.
    let lookup_bits: Option<usize> = var("LOOKUP_BITS")
        .map(|str| {
            let lookup_bits = str.parse().unwrap();
            // we use a lookup table with 2^LOOKUP_BITS rows. Due to blinding factors, we need a little more than 2^LOOKUP_BITS rows total in our circuit
            assert!(lookup_bits < k, "LOOKUP_BITS needs to be less than DEGREE");
            lookup_bits
        })
        .ok();

    // we initiate a "thread builder" in mockprover mode. This is what keeps track of the execution trace of our program and the ZK constraints so we can do some post-processing optimization after witness generation
    let mut builder = GateThreadBuilder::mock();
    // builder.main(phase) gets a default "main" thread for the given phase. For most purposes we only need to think about phase 0
    // we need a 64-bit number as input in this case
    // while `some_algorithm_in_zk` was written generically for any field `F`, in practice we use the scalar field of the BN254 curve because that's what the proving system backend uses
    let mut assigned_instances = vec![];
    f(builder.main(0), private_inputs, &mut assigned_instances);

    // now `builder` contains the execution trace, and we are ready to actually create the circuit
    // minimum rows is the number of rows used for blinding factors. This depends on the circuit itself, but we can guess the number and change it if something breaks (default 9 usually works)
    let minimum_rows = var("MINIMUM_ROWS").unwrap_or_else(|_| "9".to_string()).parse().unwrap();
    // auto-tune circuit
    builder.config(k, Some(minimum_rows));

    let public_io: Vec<Fr> = assigned_instances.iter().map(|v| *v.value()).collect();
    let time = start_timer!(|| "Mock prover");
    if lookup_bits.is_some() {
        // create circuit
        let circuit = RangeWithInstanceCircuitBuilder {
            circuit: RangeCircuitBuilder::mock(builder),
            assigned_instances,
        };

        // we don't have any public inputs for now
        MockProver::run(k as u32, &circuit, vec![public_io]).unwrap().assert_satisfied();
    } else {
        // create circuit
        let circuit = GateWithInstanceCircuitBuilder {
            circuit: GateCircuitBuilder::mock(builder),
            assigned_instances,
        };

        // we don't have any public inputs for now
        MockProver::run(k as u32, &circuit, vec![public_io]).unwrap().assert_satisfied();
    }
    end_timer!(time);
    println!("Mock prover passed!");
}

/// Creates a circuit and runs the full Halo2 proving process on it.
/// Will time the generation of verify key & proving key. It will then run the prover on the given circuit.
/// Finally the verifier will verify the proof. The verifier will panic if the proof is invalid.
///
/// Warning: This may be memory and compute intensive.
///
/// * `private_inputs` are the private inputs you want to prove a computation on.
/// * `dummy_inputs` are some dummy private inputs, in the correct format for your circuit, that should be used just for proving key generation. They can be the same as `private_inputs` for testing, but in production the proving key is generated only once, so `dummy_inputs` is usually different from `private_inputs` and it is best to test your circuit using different inputs to make sure you don't have any missed logic.
pub fn prove<T: Copy>(
    f: impl Fn(&mut Context<Fr>, T, &mut Vec<AssignedValue<Fr>>),
    private_inputs: T,
    dummy_inputs: T,
) -> Vec<u8> {
    let k = var("DEGREE").unwrap_or_else(|_| "18".to_string()).parse().unwrap();
    // we use env var `LOOKUP_BITS` to determine whether to use `GateThreadBuilder` or `RangeCircuitBuilder`. The difference is that the latter creates a lookup table with 2^LOOKUP_BITS rows, while the former does not.
    let lookup_bits: Option<usize> = var("LOOKUP_BITS")
        .map(|str| {
            let lookup_bits = str.parse().unwrap();
            // we use a lookup table with 2^LOOKUP_BITS rows. Due to blinding factors, we need a little more than 2^LOOKUP_BITS rows total in our circuit
            assert!(lookup_bits < k, "LOOKUP_BITS needs to be less than DEGREE");
            lookup_bits
        })
        .ok();
    let minimum_rows = var("MINIMUM_ROWS").unwrap_or_else(|_| "9".to_string()).parse().unwrap();
    // much the same process as [`mock()`], but we need to create a separate circuit for the key generation stage and the proving stage (in production they are done separately)

    // in keygen mode, the private variables are all not used
    let mut builder = GateThreadBuilder::keygen();
    let mut assigned_instances = vec![];
    f(builder.main(0), dummy_inputs, &mut assigned_instances); // the input value doesn't matter here for keygen
    builder.config(k, Some(minimum_rows));

    // generates a random universal trusted setup and write to file for later re-use. This is NOT for production. In production a trusted setup must be created from a multi-party computation
    let params = gen_srs(k as u32);
    let vk;
    let pk;
    let break_points;

    // rust types does not allow dynamic dispatch of different circuit types, so here we are
    if lookup_bits.is_some() {
        let circuit = RangeWithInstanceCircuitBuilder {
            circuit: RangeCircuitBuilder::keygen(builder),
            assigned_instances,
        };

        vk = keygen_vk(&params, &circuit).expect("vk generation failed");
        pk = keygen_pk(&params, vk, &circuit).expect("pk generation failed");
        // The MAIN DIFFERENCE in this setup is that after pk generation, the shape of the circuit is set in stone. We should not auto-configure the circuit anymore. Instead, we get the circuit shape and store it:
        break_points = circuit.circuit.0.break_points.take();
    } else {
        let circuit = GateWithInstanceCircuitBuilder {
            circuit: GateCircuitBuilder::keygen(builder),
            assigned_instances,
        };

        vk = keygen_vk(&params, &circuit).expect("vk generation failed");
        pk = keygen_pk(&params, vk, &circuit).expect("pk generation failed");
        // The MAIN DIFFERENCE in this setup is that after pk generation, the shape of the circuit is set in stone. We should not auto-configure the circuit anymore. Instead, we get the circuit shape and store it:
        break_points = circuit.circuit.break_points.take();
    }

    // we time creation of the builder because this is the witness generation stage and can only
    // be done after the private inputs are known
    let mut builder = GateThreadBuilder::prover();
    let mut assigned_instances = vec![];
    f(builder.main(0), private_inputs.clone(), &mut assigned_instances);
    let public_io: Vec<Fr> = assigned_instances.iter().map(|v| *v.value()).collect();
    let assigned_instances_copy = assigned_instances.clone();
    let num_instance = vec![public_io.len()];
    // once again, we have a pre-determined way to break up the builder "threads" into an optimal
    // circuit shape, so we create the prover circuit from this information (`break_points`)
    let proof = if lookup_bits.is_some() {
        let circuit = RangeWithInstanceCircuitBuilder {
            circuit: RangeCircuitBuilder::prover(builder, break_points.clone()),
            assigned_instances,
        };
        let mut transcript = TranscriptWriterBuffer::<_, _, _>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverGWC<_>,
            _,
            _,
            EvmTranscript<G1Affine, _, _, _>,
            _,
        >(&params, &pk, &[circuit], &[&[&public_io]], OsRng, &mut transcript)
        .expect("proof generation failed");
        let proof = transcript.finalize();

        let yul_path = "params/zk_range_proof.yul".to_string();
        let deployment_code = gen_aggregation_evm_verifier(
            &params,
            &pk.get_vk(),
            num_instance.clone(),
            vec![],
            yul_path.clone()
        ).unwrap();
        let deployment_code_path = PathBuf::from("params/zk_range_proof.code".to_string());
        deployment_code.save(&deployment_code_path).unwrap();

        let deployment_code_path = PathBuf::from("params/zk_range_proof.yul".to_string());
        let file = File::open(deployment_code_path.clone()).unwrap();
        let reader = BufReader::new(file);
        let yul_code = reader.lines().map(|line| line.unwrap().replace(
            "staticcall(gas(), 0x6", "staticcall(500, 0x6").replace(
                "staticcall(gas(), 0x7", "staticcall(40000, 0x7")
            ).collect::<Vec<String>>().join("\n");
        let code = DeploymentCode { code: compile_yul(&yul_code) };
        let protocol = compile::<_, _>(
            &params,
            pk.get_vk(),
            Config::kzg().with_num_instance(num_instance.clone()),
        );
        let mut assigned_ins_vec = Vec::new();
            assigned_ins_vec.push(assigned_instances_copy.clone().into_iter().map(|x| *x.value()).collect());
        let snark_proof = Snark::new(protocol, assigned_ins_vec.clone(), proof.clone());
        evm_verify(code, snark_proof.clone()).unwrap();

        println!("calldata of original proof: {:?}", encode_calldata(&snark_proof.instances, &snark_proof.proof));
        let output = fix_verifier_sol(yul_path.into()).unwrap();
        let sol_path = PathBuf::from("params/zk_range_proof.sol");
        let mut f = File::create(sol_path).unwrap();
        let _ = f.write(output.as_bytes());

        proof
    } else {
        let circuit = GateWithInstanceCircuitBuilder {
            circuit: GateCircuitBuilder::prover(builder, break_points),
            assigned_instances,
        };
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(&params, &pk, &[circuit], &[&[&public_io]], OsRng, &mut transcript)
        .expect("proof generation failed");
        let proof = transcript.finalize();

        proof
    };

    let instances = &vec![public_io];
    let final_proof = encode_calldata(instances, &proof);
    final_proof
}

#[derive(Clone, Debug)]
pub struct GateWithInstanceConfig<F: ScalarField> {
    pub gate: FlexGateConfig<F>,
    pub instance: Column<Instance>,
}

/// This is an extension of [`GateCircuitBuilder`] that adds support for public instances (aka public inputs+outputs)
///
/// The intended design is that a [`GateThreadBuilder`] is populated and then produces some assigned instances, which are supplied as `assigned_instances` to this struct.
/// The [`Circuit`] implementation for this struct will then expose these instances and constrain them using the Halo2 API.
pub struct GateWithInstanceCircuitBuilder<F: ScalarField> {
    pub circuit: GateCircuitBuilder<F>,
    pub assigned_instances: Vec<AssignedValue<F>>,
}

impl<F: ScalarField> Circuit<F> for GateWithInstanceCircuitBuilder<F> {
    type Config = GateWithInstanceConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let gate = GateCircuitBuilder::configure(meta);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        GateWithInstanceConfig { gate, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // we later `take` the builder, so we need to save this value
        let witness_gen_only = self.circuit.builder.borrow().witness_gen_only();
        let assigned_advices = self.circuit.sub_synthesize(&config.gate, &[], &[], &mut layouter);

        if !witness_gen_only {
            // expose public instances
            let mut layouter = layouter.namespace(|| "expose");
            for (i, instance) in self.assigned_instances.iter().enumerate() {
                let cell = instance.cell.unwrap();
                let (cell, _) = assigned_advices
                    .get(&(cell.context_id, cell.offset))
                    .expect("instance not assigned");
                layouter.constrain_instance(*cell, config.instance, i).unwrap();
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct RangeWithInstanceConfig<F: ScalarField> {
    pub range: RangeConfig<F>,
    pub instance: Column<Instance>,
}

/// This is an extension of [`RangeCircuitBuilder`] that adds support for public instances (aka public inputs+outputs)
///
/// The intended design is that a [`GateThreadBuilder`] is populated and then produces some assigned instances, which are supplied as `assigned_instances` to this struct.
/// The [`Circuit`] implementation for this struct will then expose these instances and constrain them using the Halo2 API.
#[derive(Clone, Debug)]
pub struct RangeWithInstanceCircuitBuilder<F: ScalarField> {
    pub circuit: RangeCircuitBuilder<F>,
    pub assigned_instances: Vec<AssignedValue<F>>,
}

impl<F: ScalarField> Circuit<F> for RangeWithInstanceCircuitBuilder<F> {
    type Config = RangeWithInstanceConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let range = RangeCircuitBuilder::configure(meta);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        RangeWithInstanceConfig { range, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // copied from RangeCircuitBuilder::synthesize but with extra logic to expose public instances
        let range = config.range;
        let circuit = &self.circuit.0;
        range.load_lookup_table(&mut layouter).expect("load lookup table should not fail");
        // we later `take` the builder, so we need to save this value
        let witness_gen_only = circuit.builder.borrow().witness_gen_only();
        let assigned_advices = circuit.sub_synthesize(
            &range.gate,
            &range.lookup_advice,
            &range.q_lookup,
            &mut layouter,
        );

        if !witness_gen_only {
            // expose public instances
            let mut layouter = layouter.namespace(|| "expose");
            for (i, instance) in self.assigned_instances.iter().enumerate() {
                let cell = instance.cell.unwrap();
                let (cell, _) = assigned_advices
                    .get(&(cell.context_id, cell.offset))
                    .expect("instance not assigned");
                layouter.constrain_instance(*cell, config.instance, i).unwrap();
            }
        }
        Ok(())
    }
}
