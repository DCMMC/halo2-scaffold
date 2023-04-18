use halo2_base::{
    utils::{ScalarField, BigPrimeField},
    QuantumCell, Context, AssignedValue
};
use super::fixed_point::{FixedPointChip, FixedPointInstructions};

#[derive(Clone, Debug)]
pub struct LinearRegressionChip<F: ScalarField> {
    pub chip: FixedPointChip<F, 63>,
    pub lookup_bits: usize,
}

impl<F: ScalarField> LinearRegressionChip<F> {
    pub fn new(lookup_bits: usize) -> Self {
        let chip = FixedPointChip::<F, 63>::default(lookup_bits);

        Self { chip, lookup_bits }
    }

    pub fn inference<QA>(
        &self,
        ctx: &mut Context<F>,
        w: impl IntoIterator<Item = QA>,
        x: impl IntoIterator<Item = QA>,
        b: QA
    ) -> AssignedValue<F>
    where 
        F: BigPrimeField, QA: Into<QuantumCell<F>> + Copy
    {
        
        let wx = self.chip.inner_product(ctx, w, x);
        let y = self.chip.qadd(ctx, wx, b);

        y
    }
}