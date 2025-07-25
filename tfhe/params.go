package tfhe

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"math/bits"

	"github.com/sp301415/tfhe-go/math/num"
)

// TorusInt represents the integers living in the discretized torus.
// Currently, it supports Q = 2^32 and Q = 2^64 (uint32 and uint64).
type TorusInt interface {
	uint32 | uint64
}

// GadgetParametersLiteral is a structure for Gadget Decomposition,
// which is used in Lev, GSW, GLev and GGSW encryptions.
type GadgetParametersLiteral[T TorusInt] struct {
	// Base is a base of gadget. It must be power of two.
	Base T
	// Level is a length of gadget.
	Level int
}

// WithBase sets the base and returns the new GadgetParametersLiteral.
func (p GadgetParametersLiteral[T]) WithBase(base T) GadgetParametersLiteral[T] {
	p.Base = base
	return p
}

// WithLevel sets the level and returns the new GadgetParametersLiteral.
func (p GadgetParametersLiteral[T]) WithLevel(level int) GadgetParametersLiteral[T] {
	p.Level = level
	return p
}

// Compile transforms GadgetParametersLiteral to read-only GadgetParameters.
// If there is any invalid parameter in the literal, it panics.
func (p GadgetParametersLiteral[T]) Compile() GadgetParameters[T] {
	switch {
	case p.Base < 2:
		panic("Base smaller than two")
	case !num.IsPowerOfTwo(p.Base):
		panic("Base not power of two")
	case p.Level <= 0:
		panic("Level smaller than zero")
	case num.SizeT[T]() < num.Log2(p.Base)*p.Level:
		panic("Base * Level larger than Q")
	}

	return GadgetParameters[T]{
		base:    p.Base,
		logBase: num.Log2(p.Base),
		level:   p.Level,
		sizeT:   num.SizeT[T](),
	}
}

// GadgetParameters is a read-only, compiled parameters based on GadgetParametersLiteral.
type GadgetParameters[T TorusInt] struct {
	// Base is a base of gadget. It must be power of two.
	base T
	// LogBase equals log(Base).
	logBase int
	// Level is a length of gadget.
	level int
	// sizeT is the size of T in bits.
	sizeT int
}

// Base is a base of gadget. It must be power of two.
func (p GadgetParameters[T]) Base() T {
	return p.base
}

// LogBase equals log(Base).
func (p GadgetParameters[T]) LogBase() int {
	return p.logBase
}

// Level is a length of gadget.
func (p GadgetParameters[T]) Level() int {
	return p.level
}

// BaseQ returns Q / Base^(i+1) for 0 <= i < Level.
// For the most common usages i = 0 and i = Level-1, use [GadgetParameters.FirstBaseQ] and [GadgetParameters.LastBaseQ].
func (p GadgetParameters[T]) BaseQ(i int) T {
	return T(1 << (p.sizeT - (i+1)*p.logBase))
}

// FirstBaseQ returns Q / Base.
func (p GadgetParameters[T]) FirstBaseQ() T {
	return T(1 << (p.sizeT - p.logBase))
}

// LastBaseQ returns Q / Base^Level.
func (p GadgetParameters[T]) LastBaseQ() T {
	return T(1 << (p.sizeT - p.level*p.logBase))
}

// LogBaseQ returns log(Q / Base^(i+1)) for 0 <= i < Level.
// For the most common usages i = 0 and i = Level-1, use [GadgetParameters.LogFirstBaseQ] and [GadgetParameters.LogLastBaseQ].
func (p GadgetParameters[T]) LogBaseQ(i int) int {
	return p.sizeT - (i+1)*p.logBase
}

// LogFirstBaseQ returns log(Q / Base).
func (p GadgetParameters[T]) LogFirstBaseQ() int {
	return p.sizeT - p.logBase
}

// LogLastBaseQ returns log(Q / Base^Level).
func (p GadgetParameters[T]) LogLastBaseQ() int {
	return p.sizeT - p.level*p.logBase
}

// Literal returns a GadgetParametersLiteral from this GadgetParameters.
func (p GadgetParameters[T]) Literal() GadgetParametersLiteral[T] {
	return GadgetParametersLiteral[T]{
		Base:  p.base,
		Level: p.level,
	}
}

// ByteSize returns the byte size of the gadget parameters.
func (p GadgetParameters[T]) ByteSize() int {
	return 16
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	[8] Base
//	[8] Level
func (p GadgetParameters[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var buf [8]byte

	base := p.base
	binary.BigEndian.PutUint64(buf[:], uint64(base))

	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	level := p.level
	binary.BigEndian.PutUint64(buf[:], uint64(level))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	if n < int64(p.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (p *GadgetParameters[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nRead int
	var buf [8]byte

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	base := T(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	level := int(binary.BigEndian.Uint64(buf[:]))

	*p = GadgetParametersLiteral[T]{
		Base:  base,
		Level: level,
	}.Compile()

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (p GadgetParameters[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, p.ByteSize()))
	_, err = p.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (p *GadgetParameters[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := p.ReadFrom(buf)
	return err
}

// BootstrapOrder is an enum type for the order of Programmable Bootstrapping.
type BootstrapOrder int

const (
	// OrderKeySwitchBlindRotate sets the order of Programmable Bootstrapping as
	//
	//	KeySwitch -> BlindRotate -> SampleExtract
	//
	// This means that LWE keys and ciphertexts will have size
	// according to GLWEDimension.
	// Public key encryption is supported only with this order.
	OrderKeySwitchBlindRotate BootstrapOrder = iota

	// OrderBlindRotateKeySwitch sets the order of Programmable Bootstrapping as
	//
	//	BlindRotate -> SampleExtract -> KeySwitch
	//
	// This means that LWE keys and ciphertexts will have size
	// according to LWEDimension.
	// Public key encryption is not supported with this order.
	OrderBlindRotateKeySwitch
)

// ParametersLiteral is a structure for TFHE parameters.
//
// # Warning
//
// Unless you are a cryptographic expert, DO NOT set these by yourself;
// always use the default parameters provided.
type ParametersLiteral[T TorusInt] struct {
	// LWEDimension is the dimension of LWE lattice used. Usually this is denoted by n.
	LWEDimension int
	// GLWERank is the rank of GLWE lattice used. Usually this is denoted by k.
	// Length of GLWE secret key is GLWERank, and length of GLWE ciphertext is GLWERank+1.
	GLWERank int
	// PolyDegree is the degree of polynomials in GLWE entities. Usually this is denoted by N.
	PolyDegree int
	// LookUpTableSize is the size of the Lookup Table used in Blind Rotation.
	//
	// In case of Extended Bootstrapping, this may differ from PolyDegree as explained in https://eprint.iacr.org/2023/402.
	// Therefore, it must be a multiple of PolyDegree.
	// To use the original TFHE bootstrapping, set this to PolyDegree.
	//
	// If zero, then it is set to PolyDegree.
	LookUpTableSize int

	// LWEStdDev is the normalized standard deviation used for gaussian error sampling in LWE encryption.
	LWEStdDev float64
	// GLWEStdDev is the normalized standard deviation used for gaussian error sampling in GLWE encryption.
	GLWEStdDev float64

	// BlockSize is the size of block to be used for LWE key sampling.
	//
	// This is used in Block Binary Key distribution, as explained in https://eprint.iacr.org/2023/958.
	// To use the original TFHE bootstrapping, set this to 1.
	//
	// If zero, then it is set to 1.
	BlockSize int

	// MessageModulus is the modulus of the encoded message.
	MessageModulus T

	// BlindRotateParameters is the gadget parameters for Blind Rotation.
	BlindRotateParameters GadgetParametersLiteral[T]
	// KeySwitchParameters is the gadget parameters for KeySwitching.
	KeySwitchParameters GadgetParametersLiteral[T]

	// BootstrapOrder is the order of Programmable Bootstrapping.
	// If this is set to OrderKeySwitchBlindRotate, then the order is:
	//
	//	KeySwitch -> BlindRotate -> SampleExtract
	//
	// and LWE keys and ciphertexts will have size according to GLWEDimension.
	//
	// Otherwise, if this is set to OrderBlindRotateKeySwitch, the order is:
	//
	//	BlindRotate -> SampleExtract -> KeySwitch
	//
	// and LWE keys and ciphertexts will have size according to LWEDimension.
	//
	// Essentially, there is a time-memory tradeoff:
	// performing keyswitching first means that it will consume more memory,
	// but it allows to use smaller parameters which will result in faster computation.
	//
	// Moreover, public key encryption is supported only with OrderKeySwitchBlindRotate.
	//
	// If zero, then it is set to OrderKeySwitchBlindRotate.
	BootstrapOrder BootstrapOrder
}

// WithLWEDimension sets the LWEDimension and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithLWEDimension(lweDimension int) ParametersLiteral[T] {
	p.LWEDimension = lweDimension
	return p
}

// WithGLWERank sets the GLWERank and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithGLWERank(glweRank int) ParametersLiteral[T] {
	p.GLWERank = glweRank
	return p
}

// WithPolyDegree sets the PolyDegree and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithPolyDegree(polyDegree int) ParametersLiteral[T] {
	p.PolyDegree = polyDegree
	return p
}

// WithLookUpTableSize sets the LookUpTableSize and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithLookUpTableSize(lookUpTableSize int) ParametersLiteral[T] {
	p.LookUpTableSize = lookUpTableSize
	return p
}

// WithLWEStdDev sets the LWEStdDev and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithLWEStdDev(lweStdDev float64) ParametersLiteral[T] {
	p.LWEStdDev = lweStdDev
	return p
}

// WithGLWEStdDev sets the GLWEStdDev and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithGLWEStdDev(glweStdDev float64) ParametersLiteral[T] {
	p.GLWEStdDev = glweStdDev
	return p
}

// WithBlockSize sets the BlockSize and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithBlockSize(blockSize int) ParametersLiteral[T] {
	p.BlockSize = blockSize
	return p
}

// WithMessageModulus sets the MessageModulus and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithMessageModulus(messageModulus T) ParametersLiteral[T] {
	p.MessageModulus = messageModulus
	return p
}

// WithBlindRotateParameters sets the BlindRotateParameters and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithBlindRotateParameters(blindRotateParameters GadgetParametersLiteral[T]) ParametersLiteral[T] {
	p.BlindRotateParameters = blindRotateParameters
	return p
}

// WithKeySwitchParameters sets the KeySwitchParameters and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithKeySwitchParameters(keySwitchParameters GadgetParametersLiteral[T]) ParametersLiteral[T] {
	p.KeySwitchParameters = keySwitchParameters
	return p
}

// WithBootstrapOrder sets the BootstrapOrder and returns the new ParametersLiteral.
func (p ParametersLiteral[T]) WithBootstrapOrder(bootstrapOrder BootstrapOrder) ParametersLiteral[T] {
	p.BootstrapOrder = bootstrapOrder
	return p
}

// Compile transforms ParametersLiteral to read-only Parameters.
// If there is any invalid parameter in the literal, it panics.
// Default parameters are guaranteed to be compiled without panics.
//
// # Warning
//
// This method performs only basic sanity checks.
// Just because a parameter compiles does not necessarily mean it is safe or correct.
// Unless you are a cryptographic expert, DO NOT set parameters by yourself;
// always use the default parameters provided.
func (p ParametersLiteral[T]) Compile() Parameters[T] {
	if p.LookUpTableSize == 0 {
		p.LookUpTableSize = p.PolyDegree
	}
	if p.BlockSize == 0 {
		p.BlockSize = 1
	}

	switch {
	case p.LWEDimension <= 0:
		panic("LWEDimension smaller than zero")
	case p.LWEDimension > p.GLWERank*p.PolyDegree:
		panic("LWEDimension larger than GLWEDimension")
	case p.GLWERank <= 0:
		panic("GLWERank smaller than zero")
	case p.LookUpTableSize < p.PolyDegree:
		panic("LookUpTableSize smaller than PolyDegree")
	case p.LWEStdDev <= 0:
		panic("LWEStdDev smaller than zero")
	case p.GLWEStdDev <= 0:
		panic("GLWEStdDev smaller than zero")
	case p.BlockSize <= 0:
		panic("BlockSize smaller than zero")
	case p.LWEDimension%p.BlockSize != 0:
		panic("LWEDimension not multiple of BlockSize")
	case p.LookUpTableSize%p.PolyDegree != 0:
		panic("LookUpTableSize not multiple of PolyDegree")
	case !num.IsPowerOfTwo(p.PolyDegree):
		panic("PolyDegree not power of two")
	case !(p.BootstrapOrder == OrderKeySwitchBlindRotate || p.BootstrapOrder == OrderBlindRotateKeySwitch):
		panic("BootstrapOrder not valid")
	}

	return Parameters[T]{
		lweDimension:     p.LWEDimension,
		glweDimension:    p.GLWERank * p.PolyDegree,
		glweRank:         p.GLWERank,
		polyDegree:       p.PolyDegree,
		logPolyDegree:    num.Log2(p.PolyDegree),
		lookUpTableSize:  p.LookUpTableSize,
		polyExtendFactor: p.LookUpTableSize / p.PolyDegree,

		lweStdDev:  p.LWEStdDev,
		glweStdDev: p.GLWEStdDev,

		blockSize:  p.BlockSize,
		blockCount: p.LWEDimension / p.BlockSize,

		messageModulus: p.MessageModulus,
		scale:          num.DivRound(1<<(num.SizeT[T]()-1), p.MessageModulus) * 2,

		logQ:   num.SizeT[T](),
		floatQ: math.Exp2(float64(num.SizeT[T]())),

		blindRotateParameters: p.BlindRotateParameters.Compile(),
		keySwitchParameters:   p.KeySwitchParameters.Compile(),

		bootstrapOrder: p.BootstrapOrder,
	}
}

// Parameters are read-only, compiled parameters based on ParametersLiteral.
type Parameters[T TorusInt] struct {
	// LWEDimension is the dimension of LWE lattice used. Usually this is denoted by n.
	lweDimension int
	// GLWEDimension is the dimension of GLWE lattice used, which is GLWERank * PolyDegree.
	glweDimension int
	// GLWERank is the rank of GLWE lattice used. Usually this is denoted by k.
	// Length of GLWE secret key is GLWERank, and length of GLWE ciphertext is GLWERank+1.
	glweRank int
	// PolyDegree is the degree of polynomials in GLWE entities. Usually this is denoted by N.
	polyDegree int
	// LogPolyDegree equals log(PolyDegree).
	logPolyDegree int
	// LookUpTableSize is the size of Lookup Table used in Blind Rotation.
	lookUpTableSize int
	// PolyExtendFactor equals LookUpTableSize / PolyDegree.
	polyExtendFactor int

	// LWEStdDev is the normalized standard deviation used for gaussian error sampling in LWE encryption.
	lweStdDev float64
	// GLWEStdDev is the normalized standard deviation used for gaussian error sampling in GLWE encryption.
	glweStdDev float64

	// BlockSize is the size of block to be used for LWE key sampling.
	blockSize int
	// BlockCount is a number of blocks in LWESecretkey. Equal to LWEDimension / BlockSize.
	blockCount int

	// MessageModulus is the modulus of the encoded message.
	messageModulus T
	// Scale is the scaling factor used for message encoding.
	// The lower log(Scale) bits are reserved for errors.
	scale T

	// logQ is the value of log(Q), where Q is the modulus of the ciphertext.
	logQ int
	// floatQ is the value of Q as float64.
	floatQ float64

	// blindRotateParameters is the gadget parameters for Blind Rotation.
	blindRotateParameters GadgetParameters[T]
	// keySwitchParameters is the gadget parameters for KeySwitching.
	keySwitchParameters GadgetParameters[T]

	// bootstrapOrder is the order of Programmable Bootstrapping.
	bootstrapOrder BootstrapOrder
}

// DefaultLWEDimension returns the default dimension for LWE entities.
// Returns LWEDimension if BootstrapOrder is OrderBlindRotateKeySwitch,
// and GLWEDimension otherwise.
func (p Parameters[T]) DefaultLWEDimension() int {
	if p.bootstrapOrder == OrderBlindRotateKeySwitch {
		return p.lweDimension
	}
	return p.glweDimension
}

// LWEDimension is the dimension of LWE lattice used. Usually this is denoted by n.
func (p Parameters[T]) LWEDimension() int {
	return p.lweDimension
}

// GLWEDimension is the dimension of GLWE lattice used, which is GLWERank * PolyDegree.
func (p Parameters[T]) GLWEDimension() int {
	return p.glweDimension
}

// GLWERank is the dimension of GLWE lattice used. Usually this is denoted by k.
// Length of GLWE secret key is GLWERank, and length of GLWE ciphertext is GLWERank+1.
func (p Parameters[T]) GLWERank() int {
	return p.glweRank
}

// PolyDegree is the degree of polynomials in GLWE entities. Usually this is denoted by N.
func (p Parameters[T]) PolyDegree() int {
	return p.polyDegree
}

// LogPolyDegree equals log(PolyDegree).
func (p Parameters[T]) LogPolyDegree() int {
	return p.logPolyDegree
}

// LookUpTableSize is the size of LookUpTable used in Blind Rotation.
func (p Parameters[T]) LookUpTableSize() int {
	return p.lookUpTableSize
}

// PolyExtendFactor returns LookUpTableSize / PolyDegree.
func (p Parameters[T]) PolyExtendFactor() int {
	return p.polyExtendFactor
}

// DefaultLWEStdDev returns the default standard deviation for LWE entities.
// Returns LWEStdDev if BootstrapOrder is OrderBlindRotateKeySwitch,
// and GLWEStdDev otherwise.
//
// This is a normlized standard deviation.
// For actual sampling, use [Parameters.DefaultLWEStdDevQ].
func (p Parameters[T]) DefaultLWEStdDev() float64 {
	if p.bootstrapOrder == OrderBlindRotateKeySwitch {
		return p.lweStdDev
	}
	return p.glweStdDev
}

// DefaultLWEStdDevQ returns DefaultLWEStdDev * Q.
func (p Parameters[T]) DefaultLWEStdDevQ() float64 {
	if p.bootstrapOrder == OrderBlindRotateKeySwitch {
		return p.lweStdDev * p.floatQ
	}
	return p.glweStdDev * p.floatQ
}

// LWEStdDev is the standard deviation used for gaussian error sampling in LWE encryption.
//
// This is a normlized standard deviation.
// For actual sampling, use [Parameters.LWEStdDevQ].
func (p Parameters[T]) LWEStdDev() float64 {
	return p.lweStdDev
}

// LWEStdDevQ returns LWEStdDev * Q.
func (p Parameters[T]) LWEStdDevQ() float64 {
	return p.lweStdDev * p.floatQ
}

// GLWEStdDev is the standard deviation used for gaussian error sampling in GLWE encryption.
//
// This is a normlized standard deviation.
// For actual sampling, use [Parameters.GLWEStdDevQ].
func (p Parameters[T]) GLWEStdDev() float64 {
	return p.glweStdDev
}

// GLWEStdDevQ returns GLWEStdDev * Q.
func (p Parameters[T]) GLWEStdDevQ() float64 {
	return p.glweStdDev * p.floatQ
}

// BlockSize is the size of block to be used for LWE key sampling.
func (p Parameters[T]) BlockSize() int {
	return p.blockSize
}

// BlockCount is a number of blocks in LWESecretkey. Equal to LWEDimension / BlockSize.
func (p Parameters[T]) BlockCount() int {
	return p.blockCount
}

// Scale is the scaling factor used for message encoding.
// The lower log(Scale) bits are reserved for errors.
func (p Parameters[T]) Scale() T {
	return p.scale
}

// MessageModulus is the modulus of the encoded message.
func (p Parameters[T]) MessageModulus() T {
	return p.messageModulus
}

// LogQ is the value of log(Q), where Q is the modulus of the ciphertext.
func (p Parameters[T]) LogQ() int {
	return p.logQ
}

// BlindRotateParameters is the gadget parameters for Programmable Bootstrapping.
func (p Parameters[T]) BlindRotateParameters() GadgetParameters[T] {
	return p.blindRotateParameters
}

// KeySwitchParameters is the gadget parameters for KeySwitching.
func (p Parameters[T]) KeySwitchParameters() GadgetParameters[T] {
	return p.keySwitchParameters
}

// BootstrapOrder is the order of Programmable Bootstrapping.
func (p Parameters[T]) BootstrapOrder() BootstrapOrder {
	return p.bootstrapOrder
}

// IsPublicKeyEncryptable returns true if public key encryption is supported.
//
// Currently, public key encryption is supported only with BootstrapOrder OrderKeySwitchBlindRotate.
func (p Parameters[T]) IsPublicKeyEncryptable() bool {
	return p.bootstrapOrder == OrderKeySwitchBlindRotate
}

// Literal returns a ParametersLiteral from this Parameters.
func (p Parameters[T]) Literal() ParametersLiteral[T] {
	return ParametersLiteral[T]{
		LWEDimension:    p.lweDimension,
		GLWERank:        p.glweRank,
		PolyDegree:      p.polyDegree,
		LookUpTableSize: p.lookUpTableSize,

		LWEStdDev:  p.lweStdDev,
		GLWEStdDev: p.glweStdDev,

		BlockSize: p.blockSize,

		MessageModulus: p.messageModulus,

		BlindRotateParameters: p.blindRotateParameters.Literal(),
		KeySwitchParameters:   p.keySwitchParameters.Literal(),

		BootstrapOrder: p.bootstrapOrder,
	}
}

// EstimateModSwitchStdDev returns an estimated standard deviation of error from modulus switching.
func (p Parameters[T]) EstimateModSwitchStdDev() float64 {
	L := float64(p.lookUpTableSize)
	q := p.floatQ

	h := float64(p.blockCount) * (float64(p.blockSize)) / (float64(p.blockSize + 1))

	modSwitchVar := ((h + 1) * q * q) / (48 * L * L)

	return math.Sqrt(modSwitchVar)
}

// EstimateModSwitchStdDev returns an estimated standard deviation of error from modulus switching.
func (p Parameters[T]) EstimateModSwitchNewStdDev() float64 {
	L := float64(p.lookUpTableSize)
	q := p.floatQ

	h := float64(p.blockCount) * (float64(p.blockSize)) / (float64(p.blockSize + 1))

	modSwitchVar := ((h + 1) * q * q) / (12 * L * L)

	return math.Sqrt(modSwitchVar)
}

// EstimateBlindRotateStdDev returns an estimated standard deviation of error from Blind Rotation.
func (p Parameters[T]) EstimateBlindRotateStdDev() float64 {
	n := float64(p.lweDimension)
	k := float64(p.glweRank)
	N := float64(p.polyDegree)
	beta := p.GLWEStdDevQ()
	q := p.floatQ

	h := float64(p.blockCount) * (float64(p.blockSize)) / (float64(p.blockSize + 1))

	Bbr := float64(p.blindRotateParameters.Base())
	Lbr := float64(p.blindRotateParameters.Level())

	blindRotateVar1 := h * (h + (k*N-n)/2 + 1) * (q * q) / (6 * math.Pow(Bbr, 2*Lbr))
	blindRotateVar2 := n * (Lbr * (k + 1) * N * beta * beta * Bbr * Bbr) / 6
	//blindRotateFFTVar := n * math.Exp2(-106.6) * (k + 1) * (h + (k*N-n)/2 + 1) * N * (q * q) * Lbr * (Bbr * Bbr)
	blindRotateVar := blindRotateVar1 + blindRotateVar2 //+ blindRotateFFTVar

	return math.Sqrt(blindRotateVar)
}

// EstimateBlindRotateStdDevNew returns an estimated standard deviation of error from Blind Rotation with our New algorithm. (without EBS)
func (p Parameters[T]) EstimateBlindRotateStdDevNew() float64 {
	depth := bits.TrailingZeros(uint(p.polyDegree / 2048))
	blindRotateVar := 0.0
	for i := 0; i < depth; i++ {
		n := float64(p.lweDimension)
		k := float64(p.glweRank)
		N := float64(p.polyDegree) / math.Pow(2, float64(i+1))
		beta := p.GLWEStdDevQ()
		q := p.floatQ

		h := float64(p.blockCount) * (float64(p.blockSize)) / (float64(p.blockSize + 1))

		Bbr := float64(p.blindRotateParameters.Base())
		Lbr := float64(p.blindRotateParameters.Level())

		blindRotateVar1 := h * (h + (k*N-n)/2 + 1) * (q * q) / (6 * math.Pow(Bbr, 2*Lbr))
		blindRotateVar2 := n * (Lbr * (k + 1) * N * beta * beta * Bbr * Bbr) / 6
		blindRotateVar += blindRotateVar1 + blindRotateVar2
		if i == depth-1 {
			blindRotateVar += blindRotateVar1 + blindRotateVar2
		}
	}
	return math.Sqrt(blindRotateVar)
}

// EstimateKeySwitchForBootstrapStdDev returns an estimated standard deviation of error from Key Switching for bootstrapping.
func (p Parameters[T]) EstimateKeySwitchForBootstrapStdDev() float64 {
	n := float64(p.lweDimension)
	k := float64(p.glweRank)
	N := float64(p.polyDegree)
	alpha := p.LWEStdDevQ()
	q := p.floatQ

	Bks := float64(p.keySwitchParameters.Base())
	Lks := float64(p.keySwitchParameters.Level())

	keySwitchVar1 := ((k*N - n) / 2) * (q * q) / (12 * math.Pow(Bks, 2*Lks))
	keySwitchVar2 := (k*N - n) * (alpha * alpha * Lks * Bks * Bks) / 12
	keySwitchVar := keySwitchVar1 + keySwitchVar2

	return math.Sqrt(keySwitchVar)
}

// EstimateKeySwitchForBootstrapStdDevNew returns an estimated standard deviation of error from Key Swithcing with our New algorithm. (without EBS)
func (p Parameters[T]) EstimateKeySwitchForBootstrapStdDevNew() float64 {
	depth := bits.TrailingZeros(uint(p.polyDegree / 2048))
	keySwitchVar := 0.0

	for i := 0; i < depth; i++ {
		n := float64(p.lweDimension)
		k := float64(p.glweRank)
		N := float64(p.polyDegree) / math.Pow(2, float64(i+1))
		alpha := p.LWEStdDevQ()
		q := p.floatQ
		Bks := float64(p.keySwitchParameters.Base())
		Lks := float64(p.keySwitchParameters.Level())
		keySwitchVar1 := ((k*N - n) / 2) * (q * q) / (12 * math.Pow(Bks, 2*Lks))
		keySwitchVar2 := (k*N - n) * (alpha * alpha * Lks * Bks * Bks) / 12
		keySwitchVar += keySwitchVar1 + keySwitchVar2
		if i == depth-1 {
			keySwitchVar += keySwitchVar1 + keySwitchVar2
		}
	}
	return math.Sqrt(keySwitchVar)
}

// EstimateMaxErrorStdDev returns an estimated standard deviation of maximum possible error.
func (p Parameters[T]) EstimateMaxErrorStdDev() float64 {
	modSwitchStdDev := p.EstimateModSwitchStdDev()
	blindRotateStdDev := p.EstimateBlindRotateStdDev()
	keySwitchStdDev := p.EstimateKeySwitchForBootstrapStdDev()
	// fmt.Printf("ModSwitch Variance (log scale): %f\n", math.Log2(modSwitchStdDev*modSwitchStdDev))
	// fmt.Printf("BlindRotate Variance (log scale): %f\n", math.Log2(blindRotateStdDev*blindRotateStdDev))
	// fmt.Printf("KeySwitch Variance (log scale): %f\n", math.Log2(keySwitchStdDev*keySwitchStdDev))
	return math.Sqrt(modSwitchStdDev*modSwitchStdDev + blindRotateStdDev*blindRotateStdDev + keySwitchStdDev*keySwitchStdDev)
}

func (p Parameters[T]) EstimateMaxErrorStdDevNewEBS() float64 {
	modSwitchStdDev := p.EstimateModSwitchNewStdDev()
	blindRotateStdDev := p.EstimateBlindRotateStdDev()
	keySwitchStdDev := p.EstimateKeySwitchForBootstrapStdDev()
	logExtendFactor := math.Log2(float64(p.polyExtendFactor))
	// fmt.Printf("ModSwitch Variance (log scale): %f\n", math.Log2(modSwitchStdDev*modSwitchStdDev))
	// fmt.Printf("BlindRotate Variance (log scale): %f\n", math.Log2((logExtendFactor+1)*blindRotateStdDev*blindRotateStdDev))
	// fmt.Printf("KeySwitch Variance (log scale): %f\n", math.Log2(keySwitchStdDev*keySwitchStdDev))
	return math.Sqrt(modSwitchStdDev*modSwitchStdDev + (logExtendFactor+1)*blindRotateStdDev*blindRotateStdDev + keySwitchStdDev*keySwitchStdDev)
}

func (p Parameters[T]) EstimateMaxErrorStdDevNew() float64 {
	modSwitchStdDev := p.EstimateModSwitchNewStdDev()
	blindRotateStdDev := p.EstimateBlindRotateStdDevNew()
	keySwitchStdDev := p.EstimateKeySwitchForBootstrapStdDevNew()
	// fmt.Printf("ModSwitch Variance (log scale): %f\n", math.Log2(modSwitchStdDev*modSwitchStdDev))
	// fmt.Printf("BlindRotate Variance (log scale): %f\n", math.Log2(blindRotateStdDev*blindRotateStdDev))
	// fmt.Printf("KeySwitch Variance (log scale): %f\n", math.Log2(keySwitchStdDev*keySwitchStdDev))
	return math.Sqrt(modSwitchStdDev*modSwitchStdDev + blindRotateStdDev*blindRotateStdDev + keySwitchStdDev*keySwitchStdDev)
}

// EstimateFailureProbability returns the failure probability of bootstrapping.
func (p Parameters[T]) EstimateFailureProbability() float64 {
	// fmt.Printf("Total Variance (log scale): %f\n", math.Log2(p.EstimateMaxErrorStdDev()*p.EstimateMaxErrorStdDev()))
	bound := p.floatQ / (4 * float64(p.messageModulus))
	return math.Erfc(bound / (math.Sqrt2 * p.EstimateMaxErrorStdDev()))
}

func (p Parameters[T]) EstimateFailureProbabilityNewFDFB_EBS() float64 {
	// fmt.Printf("Total Variance (log scale): %f\n", math.Log2(p.EstimateMaxErrorStdDevNewEBS()*p.EstimateMaxErrorStdDevNewEBS()))
	bound := p.floatQ / (2 * float64(p.messageModulus))
	return math.Erfc(bound / (math.Sqrt2 * p.EstimateMaxErrorStdDevNewEBS()))
}

func (p Parameters[T]) EstimateFailureProbabilityNewFDFB() float64 {
	// fmt.Printf("Total Variance (log scale): %f\n", math.Log2(p.EstimateMaxErrorStdDevNew()*p.EstimateMaxErrorStdDevNew()))
	bound := p.floatQ / (2 * float64(p.messageModulus))
	return math.Erfc(bound / (math.Sqrt2 * p.EstimateMaxErrorStdDevNew()))
}

// ByteSize returns the byte size of the parameters.
func (p Parameters[T]) ByteSize() int {
	return 8*8 + p.blindRotateParameters.ByteSize() + p.keySwitchParameters.ByteSize() + 1
}

// WriteTo implements the [io.WriterTo] interface.
//
// The encoded form is as follows:
//
//	[ 8] LWEDimension
//	[ 8] GLWERank
//	[ 8] PolyDegree
//	[ 8] LookUpTableSize
//	[ 8] LWEStdDev
//	[ 8] GLWEStdDev
//	[ 8] BlockSize
//	[ 8] MessageModulus
//	     BlindRotateParameters
//	     KeySwitchParameters
//	[ 1] BootstrapOrder
func (p Parameters[T]) WriteTo(w io.Writer) (n int64, err error) {
	var nWrite int
	var nWrite64 int64
	var buf [8]byte

	lweDimension := p.lweDimension
	binary.BigEndian.PutUint64(buf[:], uint64(lweDimension))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	glweRank := p.glweRank
	binary.BigEndian.PutUint64(buf[:], uint64(glweRank))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	polyDegree := p.polyDegree
	binary.BigEndian.PutUint64(buf[:], uint64(polyDegree))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	lookUpTableSize := p.lookUpTableSize
	binary.BigEndian.PutUint64(buf[:], uint64(lookUpTableSize))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	lweStdDev := math.Float64bits(p.lweStdDev)
	binary.BigEndian.PutUint64(buf[:], lweStdDev)
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	glweStdDev := math.Float64bits(p.glweStdDev)
	binary.BigEndian.PutUint64(buf[:], glweStdDev)
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	blockSize := p.blockSize
	binary.BigEndian.PutUint64(buf[:], uint64(blockSize))
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	messageModulus := uint64(p.messageModulus)
	binary.BigEndian.PutUint64(buf[:], messageModulus)
	if nWrite, err = w.Write(buf[:]); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	if nWrite64, err = p.blindRotateParameters.WriteTo(w); err != nil {
		return n + nWrite64, err
	}
	n += nWrite64

	if nWrite64, err = p.keySwitchParameters.WriteTo(w); err != nil {
		return n + nWrite64, err
	}
	n += nWrite64

	bootstrapOrder := p.bootstrapOrder
	if nWrite, err = w.Write([]byte{byte(bootstrapOrder)}); err != nil {
		return n + int64(nWrite), err
	}
	n += int64(nWrite)

	if n < int64(p.ByteSize()) {
		return n, io.ErrShortWrite
	}

	return
}

// ReadFrom implements the [io.ReaderFrom] interface.
func (p *Parameters[T]) ReadFrom(r io.Reader) (n int64, err error) {
	var nRead int
	var nRead64 int64
	var buf [8]byte

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	lweDimension := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	glweRank := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	polyDegree := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	lookUpTableSize := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	lweStdDev := math.Float64frombits(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	glweStdDev := math.Float64frombits(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	blockSize := int(binary.BigEndian.Uint64(buf[:]))

	if nRead, err = io.ReadFull(r, buf[:]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	messageModulus := T(binary.BigEndian.Uint64(buf[:]))

	var blindRotateParameters GadgetParameters[T]
	if nRead64, err = blindRotateParameters.ReadFrom(r); err != nil {
		return n + nRead64, err
	}
	n += nRead64

	var keySwitchParameters GadgetParameters[T]
	if nRead64, err = keySwitchParameters.ReadFrom(r); err != nil {
		return n + nRead64, err
	}
	n += nRead64

	if nRead, err = io.ReadFull(r, buf[:1]); err != nil {
		return n + int64(nRead), err
	}
	n += int64(nRead)
	bootstrapOrder := BootstrapOrder(buf[0])

	*p = ParametersLiteral[T]{
		LWEDimension:    lweDimension,
		GLWERank:        glweRank,
		PolyDegree:      polyDegree,
		LookUpTableSize: lookUpTableSize,

		LWEStdDev:  lweStdDev,
		GLWEStdDev: glweStdDev,

		BlockSize: blockSize,

		MessageModulus: messageModulus,

		BlindRotateParameters: blindRotateParameters.Literal(),
		KeySwitchParameters:   keySwitchParameters.Literal(),

		BootstrapOrder: bootstrapOrder,
	}.Compile()

	return
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
func (p Parameters[T]) MarshalBinary() (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0, p.ByteSize()))
	_, err = p.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
func (p *Parameters[T]) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := p.ReadFrom(buf)
	return err
}
