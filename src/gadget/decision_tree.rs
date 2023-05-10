use halo2_base::{
    utils::{ScalarField, BigPrimeField},
    QuantumCell, Context, AssignedValue
};
use log::warn;
use super::fixed_point::{FixedPointChip, FixedPointInstructions};
use std::convert::From;
use halo2_base::QuantumCell::{Constant, Existing};

#[derive(Clone, Debug)]
pub struct DecisionTreeChip<F: BigPrimeField> {
    pub chip: FixedPointChip<F, 63>,
    pub lookup_bits: usize,
}

impl<F: BigPrimeField> DecisionTreeChip<F> {
    pub fn new(lookup_bits: usize) -> Self {
        let chip = FixedPointChip::<F, 63>::default(lookup_bits);

        Self { chip, lookup_bits }
    }

    // pub fn inference<QA>(
    //     &self,
    //     ctx: &mut Context<F>,
    //     tree: impl IntoIterator<Item = impl IntoIterator<Item = QA>>,
    //     x: impl IntoIterator<Item = QA>,
    //     max_path_len: usize
    // ) -> AssignedValue<F>
    // where 
    //     F: BigPrimeField, QA: Into<QuantumCell<F>> + Copy
    // {
    //     // format of tree: [[data_index, value, left_index, right_index], ...]
    //     let mut cur_idx = Constant(F::zero());
    //     for _ in 0..max_path_len {

    //     }
    // }
}