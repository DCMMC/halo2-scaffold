use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::utils::{ScalarField, BigPrimeField};
use halo2_base::AssignedValue;
use halo2_base::Context;
use halo2_proofs::halo2curves::FieldExt;
use halo2_scaffold::gadget::fixed_point::{FixedPointChip, FixedPointInstructions};
#[allow(unused_imports)]
use halo2_scaffold::scaffold::{mock, prove};

fn some_algorithm_in_zk<F: ScalarField>(
    ctx: &mut Context<F>,
    x: F,
    make_public: &mut Vec<AssignedValue<F>>,
) where F: BigPrimeField {
    // `Context` can roughly be thought of as a single-threaded execution trace of a program we want to ZK prove. We do some post-processing on `Context` to optimally divide the execution trace into multiple columns in a PLONKish arithmetization
    // More advanced usage with multi-threaded witness generation is possible, but we do not explain it here

    // first we load a number `x` into as system, as a "witness"
    let x = ctx.load_witness(x);
    // by default, all numbers in the system are private
    // we can make it public like so:
    make_public.push(x);

    // fixed-point exp arithmetic
    let fixed_point_chip = FixedPointChip::<F>::default();
    let exp_1 = fixed_point_chip.exp(ctx, x);
    let x_decimal = (x.value().get_lower_128() as f64) / (0x100000000i64 as f64);
    let y_decimal = (exp_1.value().get_lower_128() as f64) / (0x100000000i64 as f64);
    let y_native = x_decimal.exp();
    println!(
        "###### zk-exp({:.6}) = {}, native-exp({:.6}) = {:.6}, error = {:.6} ({:.6}%)",
        x_decimal, y_decimal, x_decimal, y_native,
        (y_decimal - y_native).abs(), (y_decimal - y_native).abs() / y_native.abs() * 100.0
    );

    make_public.push(exp_1);
}

fn main() {
    env_logger::init();

    // run mock prover
    let x0 = Fr::from_u128((0x100000000i64 as f64 * 1.0) as u128);
    mock(some_algorithm_in_zk, x0);

    let x1 = Fr::from_u128((0x100000000i64 as f64 * 17.0) as u128);
    mock(some_algorithm_in_zk, x1);

    let x2 = Fr::from_u128((0x100000000i64 as f64 * 2.0) as u128);
    mock(some_algorithm_in_zk, x2);

    let x3 = Fr::from_u128((0x100000000i64 as f64 * 0.0) as u128);
    mock(some_algorithm_in_zk, x3);

    // uncomment below to run actual prover:
    // this code will works fine
    prove(some_algorithm_in_zk, x1, Fr::from_u128(
        (0x100000000i64 as f64 * 17.0) as u128)
    ); // the 3rd parameter is a dummy input to provide for the proving key generation

    // NOTE (Wentao XIAO) but if we change private_inputs to a different value compared with dummy_inputs
    // NOTE (Wentao XIAO) the prove will failed with ConstraintSystemFailure
    // NOTE (Wentao XIAO) uncomment the following lines to reproduce this error:
    // prove(some_algorithm_in_zk, x1, Fr::from_u128(
    //     (0x100000000i64 as f64 * 2.1) as u128)
    // );
}
