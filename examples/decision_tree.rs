use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::utils::{ScalarField, BigPrimeField};
use halo2_base::AssignedValue;
use halo2_base::Context;
use halo2_scaffold::gadget::decision_tree::DecisionTreeChip;
use halo2_scaffold::scaffold::{gen_key, prove_private};
#[allow(unused_imports)]
use halo2_scaffold::scaffold::{mock, prove};
use log::warn;
use std::cmp::min;
use std::env::{var, set_var};
use linfa::prelude::*;
use linfa_linear::LinearRegression;
use ndarray::{Array, Axis};
use halo2_base::QuantumCell::{Constant, Existing, Witness};

pub fn inference<F: ScalarField>(
    ctx: &mut Context<F>,
    x: Vec<f64>,
    make_public: &mut Vec<AssignedValue<F>>,
) where F: BigPrimeField {
    // `Context` can roughly be thought of as a single-threaded execution trace of a program we want to ZK prove. We do some post-processing on `Context` to optimally divide the execution trace into multiple columns in a PLONKish arithmetization
    // More advanced usage with multi-threaded witness generation is possible, but we do not explain it here

    // lookup bits must agree with the size of the lookup table, which is specified by an environmental variable
    let lookup_bits =
        var("LOOKUP_BITS").unwrap_or_else(|_| panic!("LOOKUP_BITS not set")).parse().unwrap();
    let chip = DecisionTreeChip::<F>::new(lookup_bits);

    let x_deq: Vec<F> = x.iter().map(|xi| {
        chip.chip.quantization(*xi)
    }).collect();

    let tree = [
        // node 0
        F::from(0),
        chip.chip.quantization(1.3),
        F::from(1),
        F::from(2),
        F::from(3),
        // node 1
        F::from(1),
        chip.chip.quantization(-3.5),
        F::from(3),
        F::from(4),
        F::from(3),
        // node 2
        F::from(0),
        F::from(0),
        F::from(2),
        F::from(2),
        F::from(1),
        // node 3
        F::from(0),
        F::from(0),
        F::from(3),
        F::from(3),
        F::from(1),
        // node 4
        F::from(0),
        F::from(0),
        F::from(4),
        F::from(4),
        F::from(0)];

    let y = chip.inference(ctx, &tree, &x_deq, 3);
    println!("y: {:?}", y);
    make_public.push(y);
}

fn main() {
    set_var("RUST_LOG", "warn");
    env_logger::init();
    // genrally lookup_bits is degree - 1
    set_var("LOOKUP_BITS", 15.to_string());
    set_var("DEGREE", 16.to_string());

    mock(inference, vec![-1.2, 0.1]);
    prove(inference, vec![-1.2, 0.1], vec![2.1, 3.2]);
}
