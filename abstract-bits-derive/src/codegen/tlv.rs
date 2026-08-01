use proc_macro2::{Literal, TokenStream};
use quote::{quote, quote_spanned};
use syn::Ident;
use syn::spanned::Spanned;

use crate::codegen::generics_to_fully_qualified;
use crate::model::{TlvVariant, TlvVariantKind};

pub fn read(
    variants: &[TlvVariant],
    repr: &Ident,
    enum_name: &Literal,
    offset: isize,
) -> TokenStream {
    let mut tagged_arms = Vec::new();
    let mut unknown_arm = None;
    for variant in variants {
        match &variant.kind {
            TlvVariantKind::Tagged {
                ident,
                tag,
                payload,
            } => {
                let tag_lit = Literal::usize_unsuffixed(*tag);
                let payload = generics_to_fully_qualified(payload.clone());
                tagged_arms.push(quote! {
                    #tag_lit => Self::#ident(
                        <#payload as ::abstract_bits::AbstractBits>::read_abstract_bits(
                            &mut value,
                        )
                        .map_err(|cause| cause.read_tlv(#enum_name, Some(tag as usize)))?
                    ),
                });
            }
            TlvVariantKind::Unknown {
                ident,
                tag_field,
                data_field,
            } => {
                unknown_arm = Some(quote! {
                    other => Self::#ident {
                        #tag_field: other,
                        #data_field: value.remaining_bytes(),
                    },
                });
            }
        }
    }

    quote! {
        let tag = <#repr as ::abstract_bits::AbstractBits>::read_abstract_bits(reader)
            .map_err(|cause| cause.read_tlv(#enum_name, None))?;
        let length = u8::read_abstract_bits(reader)
            .map_err(|cause| cause.read_tlv(#enum_name, Some(tag as usize)))?;

        // The value size is the length field plus the dialect's offset. With a
        // `total` length the offset is negative, so a length field smaller than
        // the header it claims to count leaves no value at all.
        let value_bytes = length as isize + #offset;
        if value_bytes < 0 {
            return Err(::abstract_bits::FromBytesError::ReadTlv {
                tag: Some(tag as usize),
                enum_name: #enum_name,
                cause: ::abstract_bits::ReadErrorCause::InvalidTlvLength {
                    ty: #enum_name,
                    got: length as usize,
                },
            });
        }

        let value_bits = value_bytes as usize * 8;
        let mut value = reader.split_off(value_bits).map_err(|cause| {
            ::abstract_bits::FromBytesError::ReadTlv {
                tag: Some(tag as usize),
                enum_name: #enum_name,
                cause: ::abstract_bits::ReadErrorCause::NotEnoughInput {
                    ty: #enum_name,
                    cause,
                },
            }
        })?;

        Ok(match tag {
            #(#tagged_arms)*
            #unknown_arm
        })
    }
}

/// The 8-bit length field caps how large a TLV value can be. A payload whose `MAX_BITS`
/// exceeds that cap can never be serialized, so reject it up front rather than
/// truncating the length at runtime.
pub fn assert_payloads_fit(
    variants: &[TlvVariant],
    enum_ident: &Ident,
    max_value_bytes: usize,
) -> TokenStream {
    let max_value_bits = Literal::usize_unsuffixed(max_value_bytes * 8);

    let bounds = variants.iter().filter_map(|variant| {
        let TlvVariantKind::Tagged { ident, payload, .. } = &variant.kind else {
            return None;
        };
        let payload = generics_to_fully_qualified(payload.clone());
        let message = Literal::string(&format!(
            "the payload of TLV variant `{enum_ident}::{ident}` can serialize to more \
             than the {max_value_bytes} bytes an 8-bit TLV length field can describe"
        ));

        Some(quote_spanned! {payload.span()=>
            const _: () = assert!(
                <#payload as ::abstract_bits::AbstractBits>::MAX_BITS <= #max_value_bits,
                #message
            );
        })
    });

    quote! { #(#bounds)* }
}

pub fn write(
    variants: &[TlvVariant],
    repr: &Ident,
    offset: isize,
    max_value_bytes: usize,
) -> TokenStream {
    let max_value_bytes = Literal::usize_unsuffixed(max_value_bytes);

    // Deriving the length from the value's real size keeps the two in sync, but the
    // value can still outgrow the length field: a `rest` list is only bounded on read,
    // and an `unknown` variant's data is a plain `Vec`.
    let length_from_value_bytes = quote! {
        let length: u8 = isize::try_from(value_bytes)
            .ok()
            .and_then(|value_bytes| value_bytes.checked_sub(#offset))
            .and_then(|length| u8::try_from(length).ok())
            .ok_or(::abstract_bits::ToBytesError::ListTooLong {
                max: #max_value_bytes,
                got: value_bytes,
            })?;
    };

    let mut arms = Vec::new();
    for variant in variants {
        match &variant.kind {
            TlvVariantKind::Tagged { ident, tag, .. } => {
                let tag_lit = Literal::usize_unsuffixed(*tag);

                arms.push(quote! {
                    Self::#ident(payload) => {
                        ::abstract_bits::AbstractBits::write_abstract_bits(
                            &(#tag_lit as #repr), writer,
                        )?;
                        let length_pos = writer.bits_written();
                        writer.skip(8).map_err(|cause|
                            ::abstract_bits::ToBytesError::BufferTooSmall {
                                ty: ::core::any::type_name::<Self>(),
                                cause,
                            })?;
                        let value_start = writer.bits_written();
                        ::abstract_bits::AbstractBits::write_abstract_bits(payload, writer)?;

                        let value_bytes = (writer.bits_written() - value_start) / 8;
                        #length_from_value_bytes

                        writer.write_u8_at(length_pos, length).map_err(|cause|
                            ::abstract_bits::ToBytesError::BufferTooSmall {
                                ty: ::core::any::type_name::<Self>(),
                                cause,
                            })?;
                    }
                });
            }
            TlvVariantKind::Unknown {
                ident,
                tag_field,
                data_field,
            } => {
                arms.push(quote! {
                    Self::#ident { #tag_field, #data_field } => {
                        ::abstract_bits::AbstractBits::write_abstract_bits(#tag_field, writer)?;

                        let value_bytes = #data_field.len();
                        #length_from_value_bytes

                        ::abstract_bits::AbstractBits::write_abstract_bits(&length, writer)?;

                        for byte in #data_field.iter() {
                            ::abstract_bits::AbstractBits::write_abstract_bits(byte, writer)?;
                        }
                    }
                });
            }
        }
    }

    quote! {
        match self {
            #(#arms)*
        }
        Ok(())
    }
}
