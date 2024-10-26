use crate::helpers::*;
use darling::FromMeta;
use proc_macro::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::{
    parse_macro_input, parse_str, AttributeArgs, Block, ExprClosure, GenericArgument, Ident,
    ItemFn, PathArguments, ReturnType, Type,
};

#[derive(FromMeta)]
struct IOMacroArgs {
    map_error: String,
    #[darling(default)]
    redis: bool,
    #[darling(default)]
    cache_prefix_block: Option<String>,
    #[darling(default)]
    name: Option<String>,
    #[darling(default)]
    time: Option<u64>,
    #[darling(default)]
    time_refresh: Option<bool>,
    #[darling(default)]
    key: Option<String>,
    #[darling(default)]
    convert: Option<String>,
    #[darling(default)]
    with_cached_flag: bool,
    #[darling(default, rename = "type")]
    cache_type: Option<String>,
    #[darling(default, rename = "create")]
    cache_create: Option<String>,
}

/// # Attributes
/// - `map_error`: (string, expr closure) specify a closure used to map any IO-store errors into
///   the error type returned by your function.
/// - `name`: (optional, string) specify the name for the generated cache, defaults to the function name uppercase.
/// - `redis`: (optional, bool) default to a `RedisCache` or `AsyncRedisCache`
/// - `time`: (optional, u64) specify a cache TTL in seconds, implies the cache type is a `TimedCached` or `TimedSizedCache`.
/// - `time_refresh`: (optional, bool) specify whether to refresh the TTL on cache hits.
/// - `type`: (optional, string type) explicitly specify the cache store type to use.
/// - `cache_prefix_block`: (optional, string expr) specify an expression used to create the string used as a
///   prefix for all cache keys of this function, e.g. `cache_prefix_block = r##"{ "my_prefix" }"##`.
///   When not specified, the cache prefix will be constructed from the name of the function. This
///   could result in unexpected conflicts between io_cached-functions of the same name, so it's
///   recommended that you specify a prefix you're sure will be unique.
/// - `create`: (optional, string expr) specify an expression used to create a new cache store, e.g. `create = r##"{ CacheType::new() }"##`.
/// - `key`: (optional, string type) specify what type to use for the cache key, e.g. `type = "TimedCached<u32, u32>"`.
///    When `key` is specified, `convert` must also be specified.
/// - `convert`: (optional, string expr) specify an expression used to convert function arguments to a cache
///   key, e.g. `convert = r##"{ format!("{}:{}", arg1, arg2) }"##`. When `convert` is specified,
///   `key` or `type` must also be set.
/// - `with_cached_flag`: (optional, bool) If your function returns a `cached::Return` or `Result<cached::Return, E>`,
///   the `cached::Return.was_cached` flag will be updated when a cached value is returned.
///
/// ## Note
/// The `type`, `create`, `key`, and `convert` attributes must be in a `String`
/// This is because darling, which is used for parsing the attributes, does not support directly parsing
/// attributes into `Type`s or `Block`s.
pub fn io_cached(args: TokenStream, input: TokenStream) -> TokenStream {
    let attr_args = parse_macro_input!(args as AttributeArgs);
    let args = match IOMacroArgs::from_list(&attr_args) {
        Ok(v) => v,
        Err(e) => {
            return TokenStream::from(e.write_errors());
        }
    };
    let input = parse_macro_input!(input as ItemFn);

    // pull out the parts of the input
    let mut attributes = input.attrs;
    let visibility = input.vis;
    let signature = input.sig;
    let body = input.block;

    // pull out the parts of the function signature
    let fn_ident = signature.ident.clone();
    let inputs = signature.inputs.clone();
    let output = signature.output.clone();
    let asyncness = signature.asyncness;

    let input_tys = get_input_types(&inputs);

    let input_names = get_input_names(&inputs);

    // pull out the output type
    let output_ty = match &output {
        ReturnType::Default => quote! {()},
        ReturnType::Type(_, ty) => quote! {#ty},
    };

    let output_span = output_ty.span();
    let output_ts = TokenStream::from(output_ty);
    let output_parts = get_output_parts(&output_ts);
    let output_string = output_parts.join("::");
    let output_type_display = output_ts.to_string().replace(' ', "");

    // if `with_cached_flag = true`, then enforce that the return type
    // is something wrapped in `Return`. Either `Return<T>` or the
    // fully qualified `cached::Return<T>`
    if args.with_cached_flag
        && !output_string.contains("Return")
        && !output_string.contains("cached::Return")
    {
        return syn::Error::new(
            output_span,
            format!(
                "\nWhen specifying `with_cached_flag = true`, \
                    the return type must be wrapped in `cached::Return<T>`. \n\
                    The following return types are supported: \n\
                    |    `Result<cached::Return<T>, E>`\n\
                    Found type: {t}.",
                t = output_type_display
            ),
        )
        .to_compile_error()
        .into();
    }

    // Find the type of the value to store.
    // Return type always needs to be a result, so we want the (first) inner type.
    // For Result<i32, String>, store i32, etc.
    let cache_value_ty = match output.clone() {
        ReturnType::Default => {
            panic!(
                "#[io_cached] functions must return `Result`s, found {:?}",
                output_type_display
            );
        }
        ReturnType::Type(_, ty) => {
            if let Type::Path(typepath) = *ty {
                let segments = typepath.path.segments;
                if let PathArguments::AngleBracketed(brackets) = &segments.last().unwrap().arguments
                {
                    let inner_ty = brackets.args.first().unwrap();
                    if output_string.contains("Return") || output_string.contains("cached::Return")
                    {
                        if let GenericArgument::Type(Type::Path(typepath)) = inner_ty {
                            let segments = &typepath.path.segments;
                            if let PathArguments::AngleBracketed(brackets) =
                                &segments.last().unwrap().arguments
                            {
                                let inner_ty = brackets.args.first().unwrap();
                                quote! {#inner_ty}
                            } else {
                                panic!(
                                    "#[io_cached] unable to determine cache value type, found {:?}",
                                    output_type_display
                                );
                            }
                        } else {
                            panic!(
                                "#[io_cached] unable to determine cache value type, found {:?}",
                                output_type_display
                            );
                        }
                    } else {
                        quote! {#inner_ty}
                    }
                } else {
                    panic!("#[io_cached] functions must return `Result`s")
                }
            } else {
                panic!(
                    "function return type too complex, #[io_cached] functions must return `Result`s"
                )
            }
        }
    };

    // make the cache identifier
    let cache_ident = match args.name {
        Some(ref name) => Ident::new(name, fn_ident.span()),
        None => Ident::new(&fn_ident.to_string().to_uppercase(), fn_ident.span()),
    };

    let (cache_key_ty, key_convert_block) = make_cache_key_type(
        &args.key,
        &args.convert,
        &args.cache_type,
        input_tys,
        &input_names,
    );

    // make the cache type and create statement
    let (cache_ty, cache_create) = match (
        &args.redis,
        &args.time,
        &args.time_refresh,
        &args.cache_prefix_block,
        &args.cache_type,
        &args.cache_create,
    ) {
        (true, time, time_refresh, cache_prefix, cache_type, cache_create) => {
            let cache_ty = match cache_type {
                Some(cache_type) => {
                    let cache_type =
                        parse_str::<Type>(cache_type).expect("unable to parse cache type");
                    quote! { #cache_type }
                }
                None => {
                    if asyncness.is_some() {
                        quote! { cached::AsyncRedisCache<#cache_key_ty, #cache_value_ty> }
                    } else {
                        quote! { cached::RedisCache<#cache_key_ty, #cache_value_ty> }
                    }
                }
            };
            let cache_create = match cache_create {
                Some(cache_create) => {
                    if time.is_some() || time_refresh.is_some() || cache_prefix.is_some() {
                        panic!("cannot specify `time`, `time_refresh`, or `cache_prefix` when passing `create block");
                    } else {
                        let cache_create = parse_str::<Block>(cache_create.as_ref())
                            .expect("unable to parse cache create block");
                        quote! { #cache_create }
                    }
                }
                None => {
                    if time.is_none() {
                        if asyncness.is_some() {
                            panic!("AsyncRedisCache requires a `time` when `create` block is not specified")
                        } else {
                            panic!(
                                "RedisCache requires a `time` when `create` block is not specified"
                            )
                        };
                    } else {
                        let cache_prefix = if let Some(cp) = cache_prefix {
                            cp.to_string()
                        } else {
                            format!(" {{ \"cached::proc_macro::io_cached::{}\" }}", cache_ident)
                        };
                        let cache_prefix = parse_str::<Block>(cache_prefix.as_ref())
                            .expect("unable to parse cache_prefix_block");
                        match time_refresh {
                            Some(time_refresh) => {
                                if asyncness.is_some() {
                                    quote! { cached::AsyncRedisCache::new(#cache_prefix, #time).set_refresh(#time_refresh).build().await.expect("error constructing AsyncRedisCache in #[io_cached] macro") }
                                } else {
                                    quote! {
                                        cached::RedisCache::new(#cache_prefix, #time).set_refresh(#time_refresh).build().expect("error constructing RedisCache in #[io_cached] macro")
                                    }
                                }
                            }
                            None => {
                                if asyncness.is_some() {
                                    quote! { cached::AsyncRedisCache::new(#cache_prefix, #time).build().await.expect("error constructing AsyncRedisCache in #[io_cached] macro") }
                                } else {
                                    quote! {
                                        cached::RedisCache::new(#cache_prefix, #time).build().expect("error constructing RedisCache in #[io_cached] macro")
                                    }
                                }
                            }
                        }
                    }
                }
            };
            (cache_ty, cache_create)
        }
        (_, time, time_refresh, cache_prefix, cache_type, cache_create) => {
            let cache_ty = match cache_type {
                Some(cache_type) => {
                    let cache_type =
                        parse_str::<Type>(cache_type).expect("unable to parse cache type");
                    quote! { #cache_type }
                }
                None => panic!("#[io_cached] cache `type` must be specified"),
            };
            let cache_create = match cache_create {
                Some(cache_create) => {
                    if time.is_some() || time_refresh.is_some() || cache_prefix.is_some() {
                        panic!("cannot specify `time`, `time_refresh`, or `cache_prefix` when passing `create block");
                    } else {
                        let cache_create = parse_str::<Block>(cache_create.as_ref())
                            .expect("unable to parse cache create block");
                        quote! { #cache_create }
                    }
                }
                None => {
                    panic!("#[io_cached] cache `create` block must be specified");
                }
            };
            (cache_ty, cache_create)
        }
        #[allow(unreachable_patterns)]
        _ => panic!("#[io_cached] cache types cache type could not be determined"),
    };

    let map_error = &args.map_error;
    let map_error = parse_str::<ExprClosure>(map_error).expect("unable to parse map_error block");

    // make the set cache and return cache blocks
    let (set_cache_block, return_cache_block) = {
        let (set_cache_block, return_cache_block) = if args.with_cached_flag {
            (
                if asyncness.is_some() {
                    quote! {
                        if let Ok(result) = &result {
                            cache.cache_set(key, result.value.clone()).await.map_err(#map_error)?;
                        }
                    }
                } else {
                    quote! {
                        if let Ok(result) = &result {
                            cache.cache_set(key, result.value.clone()).map_err(#map_error)?;
                        }
                    }
                },
                quote! { let mut r = ::cached::Return::new(result.clone()); r.was_cached = true; return Ok(r) },
            )
        } else {
            (
                if asyncness.is_some() {
                    quote! {
                        if let Ok(result) = &result {
                            cache.cache_set(key, result.clone()).await.map_err(#map_error)?;
                        }
                    }
                } else {
                    quote! {
                        if let Ok(result) = &result {
                            cache.cache_set(key, result.clone()).map_err(#map_error)?;
                        }
                    }
                },
                quote! { return Ok(result.clone()) },
            )
        };
        (set_cache_block, return_cache_block)
    };

    let do_set_return_block = if asyncness.is_some() {
        quote! {
            // run the function and cache the result
            async fn inner(#inputs) #output #body;
            let result = inner(#(#input_names),*).await;
            let cache = &#cache_ident.get().await;
            #set_cache_block
            result
        }
    } else {
        quote! {
            // run the function and cache the result
            fn inner(#inputs) #output #body;
            let result = inner(#(#input_names),*);
            let cache = &#cache_ident;
            #set_cache_block
            result
        }
    };

    let signature_no_muts = get_mut_signature(signature);

    // create a signature for the cache-priming function
    let prime_fn_ident = Ident::new(&format!("{}_prime_cache", &fn_ident), fn_ident.span());
    let mut prime_sig = signature_no_muts.clone();
    prime_sig.ident = prime_fn_ident;

    // make cached static, cached function and prime cached function doc comments
    let cache_ident_doc = format!("Cached static for the [`{}`] function.", fn_ident);
    let prime_fn_indent_doc = format!("Primes the cached function [`{}`].", fn_ident);
    let cache_fn_doc_extra = format!(
        "This is a cached function that uses the [`{}`] cached static.",
        cache_ident
    );
    fill_in_attributes(&mut attributes, cache_fn_doc_extra);

    // put it all together
    let expanded = if asyncness.is_some() {
        quote! {
            // Cached static
            #[doc = #cache_ident_doc]
            ::cached::lazy_static::lazy_static! {
                #visibility static ref #cache_ident: ::cached::async_once::AsyncOnce<#cache_ty> = ::cached::async_once::AsyncOnce::new(async move { #cache_create });
            }
            // Cached function
            #(#attributes)*
            #visibility #signature_no_muts {
                use cached::IOCachedAsync;
                let key = #key_convert_block;
                {
                    // check if the result is cached
                    let cache = &#cache_ident.get().await;
                    if let Some(result) = cache.cache_get(&key).await.map_err(#map_error)? {
                        #return_cache_block
                    }
                }
                #do_set_return_block
            }
            // Prime cached function
            #[doc = #prime_fn_indent_doc]
            #[allow(dead_code)]
            #visibility #prime_sig {
                use cached::IOCachedAsync;
                let key = #key_convert_block;
                #do_set_return_block
            }
        }
    } else {
        quote! {
            // Cached static
            #[doc = #cache_ident_doc]
            #visibility static #cache_ident: ::cached::once_cell::sync::Lazy<#cache_ty> = ::cached::once_cell::sync::Lazy::new(|| #cache_create);
            // Cached function
            #(#attributes)*
            #visibility #signature_no_muts {
                use cached::IOCached;
                let key = #key_convert_block;
                {
                    // check if the result is cached
                    let cache = &#cache_ident;
                    if let Some(result) = cache.cache_get(&key).map_err(#map_error)? {
                        #return_cache_block
                    }
                }
                #do_set_return_block
            }
            // Prime cached function
            #[doc = #prime_fn_indent_doc]
            #[allow(dead_code)]
            #visibility #prime_sig {
                use cached::IOCached;
                let key = #key_convert_block;
                #do_set_return_block
            }
        }
    };

    expanded.into()
}
