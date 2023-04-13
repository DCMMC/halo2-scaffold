use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::utils::{ScalarField, BigPrimeField};
use halo2_base::AssignedValue;
use halo2_base::Context;
use halo2_proofs::halo2curves::FieldExt;
use halo2_scaffold::gadget::fixed_point::{FixedPointChip, FixedPointInstructions};
#[allow(unused_imports)]
use halo2_scaffold::scaffold::{mock, prove};
use std::env::{var, set_var};

fn some_algorithm_in_zk<F: ScalarField>(
    ctx: &mut Context<F>,
    x: f64,
    make_public: &mut Vec<AssignedValue<F>>,
) where F: BigPrimeField {
    // `Context` can roughly be thought of as a single-threaded execution trace of a program we want to ZK prove. We do some post-processing on `Context` to optimally divide the execution trace into multiple columns in a PLONKish arithmetization
    // More advanced usage with multi-threaded witness generation is possible, but we do not explain it here

    // lookup bits must agree with the size of the lookup table, which is specified by an environmental variable
    let lookup_bits =
        var("LOOKUP_BITS").unwrap_or_else(|_| panic!("LOOKUP_BITS not set")).parse().unwrap();
    // fixed-point exp arithmetic
    let fixed_point_chip = FixedPointChip::<F, 32>::default(lookup_bits);

    let x_decimal = x;
    let x = fixed_point_chip.quantization(x);
    println!("x: {:?}", x);

    // first we load a number `x` into as system, as a "witness"
    let x = ctx.load_witness(x);
    // by default, all numbers in the system are private
    // we can make it public like so:
    make_public.push(x);

    // Sanity checks
    // let test1 = fixed_point_chip.qmul30(ctx, x, x);
    // make_public.push(test1);
    // assert_eq!(x.value().get_lower_128() * x.value().get_lower_128() / (1u128 << 30), test1.value().get_lower_128());

    // let test2 = fixed_point_chip.mul(ctx, x, x);
    // make_public.push(test2);
    // assert_eq!(x.value().get_lower_128() * x.value().get_lower_128() / 0x100000000u128, test2.value().get_lower_128());

    let exp_1 = fixed_point_chip.qexp2(ctx, x);
    let y_decimal = fixed_point_chip.dequantization(*exp_1.value());
    let y_native = x_decimal.exp2();
    println!(
        "###### zk-exp({:.6}) = {}, native-exp({:.6}) = {:.6}, error = {:.6} ({:.6}%)",
        x_decimal, y_decimal, x_decimal, y_native,
        (y_decimal - y_native).abs(), (y_decimal - y_native).abs() / y_native.abs() * 100.0
    );

    // make_public.push(exp_1);
}

fn main() {
    env_logger::init();
    // genrally lookup_bits is degree - 1
    set_var("LOOKUP_BITS", 11.to_string());
    set_var("DEGREE", 13.to_string());

    // run mock prover
    mock(some_algorithm_in_zk, -12.0);
    mock(some_algorithm_in_zk, -1.88724767676867);
    mock(some_algorithm_in_zk, 0.0);
    mock(some_algorithm_in_zk, 0.1234568);
    mock(some_algorithm_in_zk, 1.0);
    mock(some_algorithm_in_zk, 1.21231);

    // uncomment below to run actual prover:
    // the 3rd parameter is a dummy input to provide for the proving key generation
    prove(
        some_algorithm_in_zk,
        -1.34,
        12.45
    );
}
