use halo2_base::{
    utils::{ScalarField, fe_to_biguint, biguint_to_fe, BigPrimeField}, gates::{GateChip, GateInstructions, RangeChip, range::RangeStrategy, RangeInstructions},
    QuantumCell, Context, AssignedValue
};
use halo2_base::QuantumCell::{Constant, Existing, Witness};
use num_integer::Integer;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FixedPointStrategy {
    Vertical, // vanilla implementation with vertical basic gate(s)
}

// #[derive(Clone, Debug)]
// pub struct FixedPointConfig<F: ScalarField> {
//     pub gate: FlexGateConfig<F>,
//     _strategy: FixedPointStrategy,
// }

// impl<F: ScalarField> FixedPointConfig<F> {
//     pub fn configure(
//         meta: &mut ConstraintSystem<F>,
//         range_strategy: FixedPointStrategy,
//         num_advice: &[usize],
//         num_fixed: usize,
//         circuit_degree: usize,
//     ) -> Self {
//         let gate = FlexGateConfig::configure(
//             meta,
//             match range_strategy {
//                 FixedPointStrategy::Vertical => GateStrategy::Vertical,
//             },
//             num_advice,
//             num_fixed,
//             circuit_degree,
//         );
//         let mut config =
//             Self { gate, _strategy: range_strategy };

//         config.gate.max_rows = 1 << circuit_degree;

//         config
//     }
// }

#[derive(Clone, Debug)]
pub struct FixedPointChip<F: ScalarField> {
    strategy: FixedPointStrategy,
    pub gate: RangeChip<F>,
    pub precision_bits: usize
}

impl<F: ScalarField> FixedPointChip<F> {
    pub fn new(strategy: FixedPointStrategy, lookup_bits: usize) -> Self {
        let gate = RangeChip::new(
            match strategy {
                FixedPointStrategy::Vertical => RangeStrategy::Vertical,
            },
            lookup_bits
        );
        let precision_bits = 64;

        Self { strategy, gate, precision_bits }
    }

    pub fn default(lookup_bits: usize) -> Self {
        Self::new(FixedPointStrategy::Vertical, lookup_bits)
    }
}

pub trait FixedPointInstructions<F: ScalarField> {
    /// Fixed point decimal and its arithmetic functions.
    /// [ref] https://github.com/XMunkki/FixPointCS/blob/c701f57c3cfe6478d1f6fd7578ae040c59386b3d/Cpp/Fixed64.h
    /// [ref] https://github.com/abdk-consulting/abdk-libraries-solidity/blob/master/ABDKMath64x64.sol
    ///
    /// TODO (Wentao XIAO) add more configurable precision, e.g., 64.64
    /// TODO (Wentao XIAO) now FixedPointChip only works on positve numbers, should support negative numbers in the future
    type Gate: GateInstructions<F>;
    type RangeGate: RangeInstructions<F>;

    fn gate(&self) -> &Self::Gate;
    fn range_gate(&self) -> &Self::RangeGate;
    fn strategy(&self) -> FixedPointStrategy;

    /// Return qmul30 of a and b for 32.32 fixed point deciamls
    fn qmul30(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<QuantumCell<F>>,
        b: impl Into<QuantumCell<F>>
    ) -> AssignedValue<F>
    where
        F: BigPrimeField;
    
    /// Return the approximation of exp2 with poly4 which is something like Taylor expansion. Precision: 18.19 bits
    fn exp2poly4(&self, ctx: &mut Context<F>, a: impl Into<QuantumCell<F>>) -> AssignedValue<F>
    where
        F: BigPrimeField;

    /// Return mul of a and b for 32.32 fixed point decimals
    fn mul(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<QuantumCell<F>>,
        b: impl Into<QuantumCell<F>>
    ) -> AssignedValue<F>
    where
        F: BigPrimeField;

    /// exp2fast
    fn exp2fast(&self, ctx: &mut Context<F>, a: impl Into<QuantumCell<F>>) -> AssignedValue<F>
    where
        F: BigPrimeField;

    /// exp
    fn exp(&self, ctx: &mut Context<F>, a: impl Into<QuantumCell<F>>) -> AssignedValue<F>
    where
        F: BigPrimeField;

    /// div mod and rem, e.g., 103 / 100 = 1 ... 3 will return 1 and 3
    fn div_mod(
        &self, ctx: &mut Context<F>, a: impl Into<QuantumCell<F>>, b: impl Into<QuantumCell<F>>
    ) -> (AssignedValue<F>, AssignedValue<F>)
    where
        F: BigPrimeField;
}

impl<F: ScalarField> FixedPointInstructions<F> for FixedPointChip<F> {
    type Gate = GateChip<F>;
    type RangeGate = RangeChip<F>;

    fn range_gate(&self) -> &Self::RangeGate {
        &self.gate
    }

    fn gate(&self) -> &Self::Gate {
        &self.gate.gate()
    }

    fn strategy(&self) -> FixedPointStrategy {
        self.strategy
    }

    fn qmul30(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<QuantumCell<F>>,
        b: impl Into<QuantumCell<F>>
    ) -> AssignedValue<F>
    where
        F: BigPrimeField,
    {
        let ab = self.gate().mul(ctx, a, b);
        let (ab30, _) = self.div_mod(ctx, Existing(ab), Constant(F::from(1 << 30)));
        ab30
    }

    fn exp2poly4(&self, ctx: &mut Context<F>, a: impl Into<QuantumCell<F>>) -> AssignedValue<F>
    where
        F: BigPrimeField,
    {
        let a = a.into();
        let y0 = self.qmul30(ctx, a, Constant(F::from(14555373)));
        let y01 = self.gate().add(ctx, y0, Constant(F::from(55869331)));
        let y1 = self.qmul30(ctx, a, y01);
        let y11 = self.gate().add(ctx, y1, Constant(F::from(259179547)));
        let y2 = self.qmul30(ctx, a, y11);
        let y21 = self.gate().add(ctx, y2, Constant(F::from(744137573)));
        let y3 = self.qmul30(ctx, a, y21);
        let y4 = self.gate().add(ctx, y3, Constant(F::from(1073741824)));
        
        y4
    }

    fn mul(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<QuantumCell<F>>,
        b: impl Into<QuantumCell<F>>
    ) -> AssignedValue<F>
    where
        F: BigPrimeField,
    {
        let y0 = self.gate().mul(ctx, a, b);
        let (y1, _) = self.div_mod(ctx, y0, Constant(F::from(0x100000000)));

        y1
    }

    fn div_mod(
        &self, ctx: &mut Context<F>, a: impl Into<QuantumCell<F>>, b: impl Into<QuantumCell<F>>
    ) -> (AssignedValue<F>, AssignedValue<F>)
    where
        F: BigPrimeField,
    {
        let a = a.into();
        let b = b.into();
        let a_num_bits = self.precision_bits / 2  + 4;
        let b_num_bits = self.precision_bits / 2 + 2;
        let (div, rem) = self.range_gate().div_mod_var(ctx, a, b, a_num_bits, b_num_bits);

        (div, rem)
    }

    fn exp2fast(&self, ctx: &mut Context<F>, a: impl Into<QuantumCell<F>>) -> AssignedValue<F>
    where
        F: BigPrimeField,
    {
        let a = a.into();
        let (_, k_rem) = self.div_mod(ctx, a, Constant(F::from(0x100000000)));
        let (k, _) = self.div_mod(ctx, k_rem, Constant(F::from(4)));
        let y0 = self.exp2poly4(ctx, k);
        let y1 = self.gate().mul(ctx, y0, Constant(F::from(4)));
        let (int_part, _) = self.div_mod(ctx, a, Constant(F::from(0x100000000)));
        let int_part_exp2 = self.gate().pow_of_two()[int_part.value().get_lower_32() as usize];
        let res = self.gate().mul(ctx, y1, Constant(int_part_exp2));

        res
    }

    fn exp(&self, ctx: &mut Context<F>, a: impl Into<QuantumCell<F>>) -> AssignedValue<F>
    where
        F: BigPrimeField
    {
        let a = a.into();
        let rcp_ln2 = Constant(F::from(0x171547652));
        let y0 = self.mul(ctx, a, rcp_ln2);
        let y1 = self.exp2fast(ctx, y0);

        y1
    }
}
