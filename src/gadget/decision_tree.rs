use halo2_base::{
    utils::BigPrimeField,
    Context, AssignedValue, gates::GateInstructions
};
use super::fixed_point::{FixedPointChip, FixedPointInstructions};
use halo2_base::QuantumCell::Constant;

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

    pub fn inference(
        &self,
        ctx: &mut Context<F>,
        tree: &[F],
        x: &[F],
        max_path_len: usize
    ) -> AssignedValue<F>
    where 
        F: BigPrimeField
    {
        // format of tree: [[data_slot, split, left_index, right_index, cls], ...]
        let zero = Constant(F::zero());
        let mut node_idx = self.chip.gate().add(ctx, zero, Constant(F::zero()));
        for _ in 0..max_path_len {
            // TODO: negatives
            let node_offset = self.chip.gate().mul(ctx, node_idx, Constant(F::from(5)));
            let data_slot_idx = self.chip.gate().add(ctx, node_offset, Constant(F::from(0)));
            let data_slot = self.chip.gate().select_from_idx(
                ctx, tree.iter().cloned().map(Constant), data_slot_idx
            );
            let mut x_copy = vec![];
            // should I add some equality constraints on these copies?
            for i in 0..x.len() {
                x_copy.push(ctx.load_witness(x[i]));
            }
            let data = self.chip.gate().select_from_idx(
                ctx, x_copy, data_slot);
            let split_idx = self.chip.gate().add(ctx, node_offset, Constant(F::from(1)));
            let split = self.chip.gate().select_from_idx(
                ctx, tree.iter().cloned().map(Constant), split_idx);
            let diff = self.chip.qsub(ctx, data, split);
            let is_less = self.chip.is_neg(ctx, diff);
            let left_idx_idx = self.chip.gate().add(ctx, node_offset, Constant(F::from(2)));
            let left_idx = self.chip.gate().select_from_idx(
                ctx, tree.iter().cloned().map(Constant), left_idx_idx);
            let right_idx_idx = self.chip.gate().add(ctx, node_offset, Constant(F::from(3)));
            let right_idx = self.chip.gate().select_from_idx(
                ctx, tree.iter().cloned().map(Constant), right_idx_idx);
            let next_idx = self.chip.gate().select(ctx, left_idx, right_idx, is_less);
            node_idx = next_idx;
        }
        let offset = self.chip.gate().mul(ctx, node_idx, Constant(F::from(5)));
        let cls_idx = self.chip.gate().add(ctx, offset, Constant(F::from(4)));
        let cls = self.chip.gate().select_from_idx(
            ctx, tree.iter().cloned().map(Constant), cls_idx);
        
        cls
    }
}