use halo2_base::utils::{ScalarField, BigPrimeField};
use halo2_base::AssignedValue;
use halo2_base::Context;
use halo2_scaffold::gadget::linear_regression::LinearRegressionChip;
#[allow(unused_imports)]
use halo2_scaffold::scaffold::{mock, prove};
use std::env::{var, set_var};
use linfa::prelude::*;
use linfa_linear::LinearRegression;
use ndarray::{Array, Axis};

fn some_algorithm_in_zk<F: ScalarField>(
    ctx: &mut Context<F>,
    x: Vec<f64>,
    make_public: &mut Vec<AssignedValue<F>>,
) where F: BigPrimeField {
    // `Context` can roughly be thought of as a single-threaded execution trace of a program we want to ZK prove. We do some post-processing on `Context` to optimally divide the execution trace into multiple columns in a PLONKish arithmetization
    // More advanced usage with multi-threaded witness generation is possible, but we do not explain it here

    // lookup bits must agree with the size of the lookup table, which is specified by an environmental variable
    let lookup_bits =
        var("LOOKUP_BITS").unwrap_or_else(|_| panic!("LOOKUP_BITS not set")).parse().unwrap();
    let chip = LinearRegressionChip::<F>::new(lookup_bits);

    let x_deq: Vec<F> = x.iter().map(|xi| {
        chip.chip.quantization(*xi)
    }).collect();
    let mut x_witness = vec![];
    for idx in 0..x_deq.len() {
        let xi = ctx.load_witness(x_deq[idx]);
        x_witness.push(xi);
        make_public.push(xi);
    }

    let dataset = linfa_datasets::diabetes();
    let lin_reg = LinearRegression::new();
    let model = lin_reg.fit(&dataset).unwrap();
    println!("intercept:  {}", model.intercept());
    println!("parameters: {}", model.params());

    // let (sample_x, _) = dataset.sample_iter().next().unwrap();
    // println!("sample_x: {:?}", sample_x);
    let sample_x = Array::from_vec(x);
    let ypred = model.predict(sample_x.insert_axis(Axis(0))).targets()[0];

    let mut w = vec![];
    for wi in model.params().iter() {
        w.push(ctx.load_witness(chip.chip.quantization(*wi)));
    }
    let b = ctx.load_witness(chip.chip.quantization(model.intercept()));
    let y_zk_raw = chip.inference(ctx, w, x_witness, b);
    let y_zk = chip.chip.dequantization(*y_zk_raw.value());
    println!(
        "###### zk-linear-regression(x) = {}, native-linear-regression(x) = {:.6}, error = {:.6} ({:.6}%)",
        y_zk, ypred,
        (y_zk - ypred).abs(), (y_zk - ypred).abs() / ypred.abs() * 100.0
    );
    make_public.push(y_zk_raw);
}

fn main() {
    env_logger::init();
    // genrally lookup_bits is degree - 1
    set_var("LOOKUP_BITS", 12.to_string());
    set_var("DEGREE", 13.to_string());

    // run mock prover
    let x = vec![
        -0.00188201652779104, -0.044641636506989, -0.0514740612388061, -0.0263278347173518,
        -0.00844872411121698, -0.019163339748222, 0.0744115640787594, -0.0394933828740919,
        -0.0683297436244215, -0.09220404962683];
    mock(
        some_algorithm_in_zk,
        x
    );

    // uncomment below to run actual prover:
    // the 3rd parameter is a dummy input to provide for the proving key generation
    prove(
        some_algorithm_in_zk,
        vec![
        10.1, -0.044641636506989, -0.0514740612388061, -0.0263278347173518,
        -0.00844872411121698, -0.019163339748222, 0.0744115640787594, -0.0394933828740919,
        -0.0683297436244215, -0.09220404962683],
        vec![
        -0.00188201652779104, -0.129089, -0.0514740612388061, -0.0263278347173518,
        -0.00844872411121698, -0.019163339748222, 0.0744115640787594, -0.0394933828740919,
        -0.0683297436244215, -0.09220404962683]
    );
}
