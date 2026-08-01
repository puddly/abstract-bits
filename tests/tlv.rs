//! Recursive Zigbee R23 TLV test case (Annex I).
use abstract_bits::{
    AbstractBits, FromBytesError, ReadErrorCause, ToBytesError, abstract_bits,
};

/// Recursive TLV enum. Each `tag` variant decodes its value as the payload
/// type from a sub-reader bounded to exactly `length + 1` bytes. The `unknown`
/// fallback captures the raw tag + value bytes for any tag we don't model.
#[abstract_bits(tlv(length = value_minus_one))]
#[derive(Debug, PartialEq)]
#[repr(u8)]
enum Tlv {
    #[abstract_bits(tag = 65)]
    SupportedKeyNegotiationMethods(SupportedKeyNegotiationMethods),
    #[abstract_bits(tag = 71)]
    FragmentationParameters(FragmentationParameters),
    #[abstract_bits(tag = 72)]
    JoinerEncapsulation(TlvList),
    #[abstract_bits(unknown)]
    Unknown { tag: u8, data: Vec<u8> },
}

#[abstract_bits]
#[derive(Debug, PartialEq, Eq)]
struct SupportedKeyNegotiationMethods {
    key_negotiation_protocols: u8,
    pre_shared_secrets: u8,
    source_device_eui64: Eui64,
}

#[abstract_bits]
#[derive(Debug, PartialEq, Eq)]
struct FragmentationParameters {
    node_id: u16,
    fragmentation_options: u8,
    max_incoming_transfer_unit: u16,
}

#[abstract_bits]
#[derive(Debug, Eq, PartialEq)]
struct Eui64(pub [u8; 8]);

/// TLVs parsed until the (sub-)reader is exhausted. Used both as the top-level
/// message body and as the value of an encapsulation TLV (recursion site).
#[abstract_bits]
#[derive(Debug, PartialEq)]
struct TlvList {
    #[abstract_bits(rest(max_bits = 2048))]
    tlvs: Vec<Tlv>,
}

#[rustfmt::skip]
fn fixture_bytes() -> Vec<u8> {
    use hex_literal::hex;
    hex!(
        "48 17"                            // Joiner Encapsulation (72), len 23
            "41 09"                        //   Supported Key Negotiation Methods (65), len 9
                "02 01"                    //     key_negotiation_protocols=0x02, pre_shared_secrets=0x01
                "ae d3 1f 0b 01 88 17 00"  //     source_device_eui64
            "2a 02"                        //   Unknown inner tag 0x2a, len 2
                "c0 ff ee"                 //     raw data (fallback must skip past it and keep parsing)
            "47 04"                        //   Fragmentation Parameters (71), len 4 -> 5 value bytes
                "00 00"                    //     node_id = 0x0000 (Trust Center)
                "01"                       //     fragmentation_options = 0x01
                "80 00"                    //     max_incoming_transfer_unit = 0x0080 = 128
        "fe 01"                            // Unknown top-level tag 0xfe, len 1
            "de ad"                        //   raw data
    ).to_vec()
}

fn fixture_value() -> TlvList {
    TlvList {
        tlvs: vec![
            Tlv::JoinerEncapsulation(TlvList {
                tlvs: vec![
                    Tlv::SupportedKeyNegotiationMethods(SupportedKeyNegotiationMethods {
                        key_negotiation_protocols: 0x02,
                        pre_shared_secrets: 0x01,
                        source_device_eui64: Eui64([
                            0xae, 0xd3, 0x1f, 0x0b, 0x01, 0x88, 0x17, 0x00,
                        ]),
                    }),
                    Tlv::Unknown {
                        tag: 0x2a,
                        data: vec![0xc0, 0xff, 0xee],
                    },
                    Tlv::FragmentationParameters(FragmentationParameters {
                        node_id: 0x0000,
                        fragmentation_options: 0x01,
                        max_incoming_transfer_unit: 0x0080,
                    }),
                ],
            }),
            Tlv::Unknown {
                tag: 0xfe,
                data: vec![0xde, 0xad],
            },
        ],
    }
}

#[test]
fn decode_recursive_tlv() {
    let parsed = TlvList::from_abstract_bytes(&fixture_bytes()).unwrap();
    assert_eq!(parsed, fixture_value());
}

#[test]
fn encode_recursive_tlv() {
    let bytes = fixture_value().to_abstract_bytes().unwrap();
    assert_eq!(bytes, fixture_bytes());
}

#[test]
fn roundtrip_recursive_tlv() {
    let bytes = fixture_bytes();
    let parsed = TlvList::from_abstract_bytes(&bytes).unwrap();
    assert_eq!(parsed.to_abstract_bytes().unwrap(), bytes);
}

/// A dialect with no off-by-one: the length field is the exact value size.
#[abstract_bits(tlv(length = value))]
#[derive(Debug, PartialEq)]
#[repr(u8)]
enum NoOffsetTlv {
    #[abstract_bits(tag = 1)]
    Pair(Pair),
    #[abstract_bits(unknown)]
    Unknown { tag: u8, data: Vec<u8> },
}

#[abstract_bits]
#[derive(Debug, PartialEq, Eq)]
struct Pair {
    a: u8,
    b: u8,
}

#[test]
fn length_offset_zero_uses_exact_length() {
    // With length = value the length byte is the value size itself (0x02),
    // not value-minus-one as in R23.
    let bytes = hex::decode("0102aabb").unwrap();
    let tlv = NoOffsetTlv::from_abstract_bytes(&bytes).unwrap();

    assert_eq!(tlv, NoOffsetTlv::Pair(Pair { a: 0xaa, b: 0xbb }));
    assert_eq!(tlv.to_abstract_bytes().unwrap(), bytes);
}

/// A dialect where the length field counts the whole TLV: tag + length + value.
#[abstract_bits(tlv(length = total))]
#[derive(Debug, PartialEq)]
#[repr(u8)]
enum TotalTlv {
    #[abstract_bits(tag = 1)]
    Pair(Pair),
    #[abstract_bits(unknown)]
    Unknown { tag: u8, data: Vec<u8> },
}

#[test]
fn length_total_counts_whole_tlv() {
    // With length = total the length byte is tag(1) + length(1) + value(2) = 0x04,
    // so the value carried is `length - 2` bytes.
    let known = hex::decode("0104aabb").unwrap();
    let tlv = TotalTlv::from_abstract_bytes(&known).unwrap();
    assert_eq!(tlv, TotalTlv::Pair(Pair { a: 0xaa, b: 0xbb }));
    assert_eq!(tlv.to_abstract_bytes().unwrap(), known);

    // The header is counted for the unknown fallback too: 2 + 2 = 0x04.
    let unknown = hex::decode("09040708").unwrap();
    let tlv = TotalTlv::from_abstract_bytes(&unknown).unwrap();
    assert_eq!(
        tlv,
        TotalTlv::Unknown {
            tag: 0x09,
            data: vec![0x07, 0x08],
        }
    );
    assert_eq!(tlv.to_abstract_bytes().unwrap(), unknown);
}

#[test]
fn length_total_below_header_size_is_an_error() {
    // With length = total the length byte counts the 2 header bytes, so 0 and 1
    // describe a TLV smaller than its own header.
    for length in [0x00, 0x01] {
        assert_eq!(
            TotalTlv::from_abstract_bytes(&[0x09, length]),
            Err(FromBytesError::ReadTlv {
                tag: Some(0x09),
                enum_name: "TotalTlv",
                cause: ReadErrorCause::InvalidTlvLength {
                    ty: "TotalTlv",
                    got: length as usize,
                },
            })
        );
    }

    // A length of exactly the header size is a well-formed, empty value.
    assert_eq!(
        TotalTlv::from_abstract_bytes(&[0x09, 0x02]),
        Ok(TotalTlv::Unknown {
            tag: 0x09,
            data: vec![],
        })
    );
}

/// A payload of exactly the largest size the length field can describe. That
/// the type compiles at all is the assertion: a payload one byte larger fails
/// the generated `MAX_BITS` bound at compile time.
#[abstract_bits]
#[derive(Debug, PartialEq, Eq)]
struct MaxValue {
    data: [u8; 255],
}

#[abstract_bits(tlv(length = value))]
#[derive(Debug, PartialEq)]
#[repr(u8)]
enum MaxValueTlv {
    #[abstract_bits(tag = 1)]
    MaxValue(MaxValue),
    #[abstract_bits(unknown)]
    Unknown { tag: u8, data: Vec<u8> },
}

#[test]
fn payload_of_exactly_max_value_size_roundtrips() {
    let tlv = MaxValueTlv::MaxValue(MaxValue { data: [0xab; 255] });
    let bytes = tlv.to_abstract_bytes().unwrap();

    assert_eq!(bytes.len(), 2 + 255);
    assert_eq!(bytes[1], 255);
    assert_eq!(MaxValueTlv::from_abstract_bytes(&bytes).unwrap(), tlv);
}

#[test]
fn unknown_value_too_long_for_the_length_field_is_an_error() {
    // `length = value` spends none of the length field on the header, so the value caps
    // at the 255 a u8 can describe.
    let at_max = MaxValueTlv::Unknown {
        tag: 0xfe,
        data: vec![0xab; 255],
    };
    assert_eq!(at_max.to_abstract_bytes().unwrap().len(), 2 + 255);

    let over_max = MaxValueTlv::Unknown {
        tag: 0xfe,
        data: vec![0xab; 256],
    };
    assert_eq!(
        over_max.to_abstract_bytes(),
        Err(ToBytesError::ListTooLong { max: 255, got: 256 })
    );
}

#[test]
fn unknown_value_cap_follows_the_length_flavor() {
    // `length = total` spends 2 of the 255 on the header, capping the value at 253.
    let at_max = TotalTlv::Unknown {
        tag: 0xfe,
        data: vec![0xab; 253],
    };
    assert_eq!(at_max.to_abstract_bytes().unwrap()[1], 255);

    let over_max = TotalTlv::Unknown {
        tag: 0xfe,
        data: vec![0xab; 254],
    };
    assert_eq!(
        over_max.to_abstract_bytes(),
        Err(ToBytesError::ListTooLong { max: 253, got: 254 })
    );
}
