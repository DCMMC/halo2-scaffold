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
    values: [F; 3],
    make_public: &mut Vec<AssignedValue<F>>,
) {
    // `Context` can roughly be thought of as a single-threaded execution trace of a program we want to ZK prove. We do some post-processing on `Context` to optimally divide the execution trace into multiple columns in a PLONKish arithmetization
    // More advanced usage with multi-threaded witness generation is possible, but we do not explain it here

    // lookup bits must agree with the size of the lookup table, which is specified by an environmental variable
    let lookup_bits =
        var("LOOKUP_BITS").unwrap_or_else(|_| panic!("LOOKUP_BITS not set")).parse().unwrap();
    // first we load a private input `x`
    // let x = ctx.load_witness(x);
    // make it public
    // make_public.push(x);

    // create a Range chip that contains methods for basic arithmetic operations
    let range = RangeChip::default(lookup_bits);

    // check that `x` is in [0, 2^64)
    let range_bits = 32;
    let [x, lower, upper] = values.map(
        |x| ctx.load_witness(x));
    make_public.extend([x, lower, upper]);
    range.range_check(ctx, x, range_bits);
    range.range_check(ctx, lower, range_bits);
    range.range_check(ctx, upper, range_bits);
    range.is_less_than(ctx, lower, upper, range_bits);
    let a = range.is_less_than(ctx, x, lower, range_bits);
    let b = range.is_less_than(ctx, a, upper, range_bits);
    let c = range.gate().add(ctx, a, Constant(F::one()));
    let d = range.gate().and(ctx, c, b);
    range.gate().assert_bit(ctx, d);
    let e = range.gate().sub(ctx, d, Constant(F::one()));
    let out = range.gate().is_zero(ctx, e);
    println!("range check: {:?}", out.value());
    make_public.push(out);

    // RangeChip contains GateChip so you can still do basic operations:
    let _sum = range.gate().add(ctx, x, x);
}

fn main() {
    env_logger::init();
    set_var("LOOKUP_BITS", 10.to_string());
    set_var("DEGREE", 11.to_string());

    // run mock prover
    mock(some_algorithm_in_zk, [Fr::from(101), Fr::from(100), Fr::from(200)]);

    // uncomment below to run actual prover:
    prove(
        some_algorithm_in_zk, 
        [Fr::from(101), Fr::from(100), Fr::from(200)], 
        [Fr::from(40), Fr::from(20), Fr::from(30)]);
}
