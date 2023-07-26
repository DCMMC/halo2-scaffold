use halo2_base::gates::{GateInstructions, RangeChip, RangeInstructions};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::utils::ScalarField;
use halo2_base::{AssignedValue, Context};
#[allow(unused_imports)]
use halo2_scaffold::scaffold::{mock, prove};
use std::env::{var, set_var};
use halo2_base::QuantumCell::Constant;

fn some_algorithm_in_zk<F: ScalarField>(
    ctx: &mut Context<F>,
    values: [F; 9],
    make_public: &mut Vec<AssignedValue<F>>,
) {
    let lookup_bits =
        var("LOOKUP_BITS").unwrap_or_else(|_| panic!("LOOKUP_BITS not set")).parse().unwrap();
    let range = RangeChip::default(lookup_bits);
    // check that `x` is in [0, 2^64)
    let range_bits = 64;
    let values = values.map(|x| ctx.load_witness(x));
    let lower_assigned = values[7];
    let upper_assigned = values[8];
    make_public.extend([values[6], lower_assigned, upper_assigned]);
    let x = range.gate().select_from_idx(ctx, (&values[0..6]).to_vec(), values[6]);
    range.range_check(ctx, x, range_bits);
    range.range_check(ctx, lower_assigned, range_bits);
    range.range_check(ctx, upper_assigned, range_bits);
    range.is_less_than(ctx, lower_assigned, upper_assigned, range_bits);
    let a = range.is_less_than(ctx, x, lower_assigned, range_bits);
    let b = range.is_less_than(ctx, x, upper_assigned, range_bits);
    let out_a = range.gate().is_equal(ctx, a, Constant(F::zero()));
    let out_b = range.gate().is_equal(ctx, b, Constant(F::one()));
    let out_ab = range.gate().and(ctx, out_a, out_b);
    let out = range.gate().is_equal(ctx, out_ab, Constant(F::one()));
    // println!("range check: {:?} <= {:?} < {:?} : {:?}", lower_assigned.value(), x.value(), upper_assigned.value(), out.value());
    make_public.push(out);
}

fn main() {
    set_var("RUST_LOG", "debug");
    env_logger::init();
    set_var("LOOKUP_BITS", 8.to_string());
    set_var("DEGREE", 9.to_string());
    // set_var("GEN_AGG_EVM", "params/zk_range_agg_evm.code");

    // run mock prover
    // uncomment below to run actual prover:
    let p = prove(
        some_algorithm_in_zk, 
        [
            Fr::from(99), Fr::from(120), Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0),
            Fr::from(1), Fr::from(100), Fr::from(200)
        ],
        [
            Fr::from(99), Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0),
            Fr::from(0), Fr::from(100), Fr::from(200)
        ]);
    println!("{p:?}");
}
