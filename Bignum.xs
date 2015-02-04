#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <openssl/ssl.h>
#include <openssl/bn.h>

#define checkOpenSslCall( result ) if( ! ( result ) ) \
  croak( "OpenSSL error: %s", ERR_reason_error_string( ERR_get_error() ) );

typedef BIGNUM *Crypt__OpenSSL__Bignum;
typedef BN_CTX *Crypt__OpenSSL__Bignum__CTX;

SV* new_obj( SV * p_proto, void* obj )
{
    SV * tmp = sv_newmortal();
    sv_setref_pv(tmp, "Crypt::OpenSSL::Bignum", (void*)obj);
    return tmp;
}

#define proto_obj( obj ) new_obj( ST(0), obj )

BIGNUM* sv2bn( SV* sv )
{
    if (SvROK(sv) && sv_derived_from(sv, "Crypt::OpenSSL::Bignum")) {
        return INT2PTR(Crypt__OpenSSL__Bignum, SvIV((SV*)SvRV(sv)));
    }
    else Perl_croak(aTHX_ "argument is not a Crypt::OpenSSL::Bignum object");
}

MODULE = Crypt::OpenSSL::Bignum      PACKAGE = Crypt::OpenSSL::Bignum   PREFIX=BN_

BOOT:
    ERR_load_crypto_strings();

void
DESTROY(Crypt::OpenSSL::Bignum self)
    CODE:
        BN_clear_free( self );

Crypt::OpenSSL::Bignum
new_from_word(CLASS, p_word)
    unsigned long p_word;
  PREINIT:
    BIGNUM* bn;
  CODE:
    checkOpenSslCall( bn = BN_new() );
    checkOpenSslCall( BN_set_word( bn, p_word ) );
    RETVAL = bn;
  OUTPUT:
    RETVAL

Crypt::OpenSSL::Bignum
new_from_decimal(CLASS, p_dec_string)
    char* p_dec_string;
  PREINIT:
    BIGNUM* bn;
  CODE:
    bn = NULL;
    checkOpenSslCall( BN_dec2bn( &bn, p_dec_string ) );
    RETVAL = bn;
  OUTPUT:
    RETVAL

Crypt::OpenSSL::Bignum
new_from_hex(CLASS, p_hex_string)
    char* p_hex_string;
  PREINIT:
    BIGNUM* bn;
  CODE:
    bn = NULL;
    checkOpenSslCall( BN_hex2bn( &bn, p_hex_string ) );
    RETVAL = bn;
  OUTPUT:
    RETVAL

Crypt::OpenSSL::Bignum
new_from_bin(CLASS, p_bin_string_SV)
    SV* p_bin_string_SV;
  PREINIT:
    BIGNUM* bn;
    char* bin;
    STRLEN bin_length;
  CODE:
    bin = SvPV( p_bin_string_SV, bin_length );
    checkOpenSslCall( bn = BN_bin2bn( bin, bin_length, NULL ) );
    RETVAL = bn;
  OUTPUT:
    RETVAL

Crypt::OpenSSL::Bignum
zero(CLASS)
  PREINIT:
    BIGNUM *bn;
  CODE:
    checkOpenSslCall( bn = BN_new() );
    checkOpenSslCall( BN_zero( bn ) );
    RETVAL = bn;
  OUTPUT:
    RETVAL

Crypt::OpenSSL::Bignum
one(CLASS)
  PREINIT:
    BIGNUM *bn;
  CODE:
    checkOpenSslCall( bn = BN_new() );
    checkOpenSslCall( BN_one( bn ) );
    RETVAL = bn;
  OUTPUT:
    RETVAL

char*
to_decimal(Crypt::OpenSSL::Bignum self)
  CODE:
    checkOpenSslCall( RETVAL = BN_bn2dec( self ) );
  OUTPUT:
    RETVAL
  CLEANUP:
    OPENSSL_free( RETVAL );

char*
to_hex(Crypt::OpenSSL::Bignum self)
  CODE:
    checkOpenSslCall( RETVAL = BN_bn2hex( self ) );
  OUTPUT:
    RETVAL
  CLEANUP:
    OPENSSL_free( RETVAL );

SV*
to_bin(Crypt::OpenSSL::Bignum self)
  PREINIT:
    unsigned char* bin;
    int length;
  CODE:
    length = BN_num_bytes( self );
    if (length>0) {
      RETVAL = NEWSV(0, length);
      SvPOK_only(RETVAL);
      SvCUR_set(RETVAL, length);
      bin = (unsigned char *)SvPV_nolen(RETVAL);
      BN_bn2bin( self, bin );
    }
    else {
      RETVAL = newSVpvn("", 0);
    }
  OUTPUT:
    RETVAL

unsigned long
BN_get_word(Crypt::OpenSSL::Bignum self)

SV*
add(a, b, ...)
    Crypt::OpenSSL::Bignum a;
    Crypt::OpenSSL::Bignum b;
  PREINIT:
    BIGNUM *bn;
  PPCODE:
    if( items > 3 )
      croak( "usage: $bn->add( $bn2[, $target] )" );
    bn = ( items < 3 ) ? BN_new() : sv2bn( ST(2) );
    checkOpenSslCall( BN_add( bn, a, b ) );
    ST(0) = ( (items < 3 ) ? proto_obj( bn ) : ST(2) );
    XSRETURN(1);

SV*
sub(a, b, ...)
    Crypt::OpenSSL::Bignum a;
    Crypt::OpenSSL::Bignum b;
  PREINIT:
    BIGNUM *bn;
  PPCODE:
    if( items > 3 )
      croak( "usage: $bn->sub( $bn2[, $target] )" );
    bn = ( items < 3 ) ? BN_new() : sv2bn( ST(2) );
    checkOpenSslCall( BN_sub( bn, a, b ) );
    ST(0) = ( (items < 3 ) ? proto_obj( bn ) : ST(2) );
    XSRETURN(1);

SV*
mul(a, b, ctx, ...)
    Crypt::OpenSSL::Bignum a;
    Crypt::OpenSSL::Bignum b;
    Crypt::OpenSSL::Bignum::CTX ctx;
  PREINIT:
    BIGNUM* bn;
  PPCODE:
    if( items > 4 )
      croak( "usage: $bn->mul( $bn2, $ctx, [, $target] )" );
    bn = ( items < 4 ) ? BN_new() : sv2bn( ST(3) );
    checkOpenSslCall( BN_mul( bn, a, b, ctx ) );
    ST(0) = ( (items < 4 ) ? proto_obj( bn ) : ST(3) );
    XSRETURN(1);

SV*
div(a, b, ctx, ...)
    Crypt::OpenSSL::Bignum a;
    Crypt::OpenSSL::Bignum b;
    Crypt::OpenSSL::Bignum::CTX ctx;
  PREINIT:
    BIGNUM* quotient;
    BIGNUM* remainder;
  PPCODE:
    if( items > 5 )
      croak( "usage: $bn->add( $bn2, $ctx, [, $quotient [, $remainder ] ] )" );
    quotient = ( items < 4 ) ? BN_new() : sv2bn( ST(3) );
    remainder = ( items < 5 ) ? BN_new() : sv2bn( ST(4) );
    checkOpenSslCall( BN_div( quotient, remainder, a, b, ctx ) );
    ST(0) = ( (items < 4 ) ? proto_obj( quotient ) : ST(3) );
    ST(1) = ( (items < 5 ) ? proto_obj( remainder ) : ST(4) );
    XSRETURN(2);

Crypt::OpenSSL::Bignum
sqr(a, ctx)
    Crypt::OpenSSL::Bignum a;
    Crypt::OpenSSL::Bignum::CTX ctx;
  PREINIT:
    BIGNUM* bn;
    SV* p_proto;
  CODE:
    p_proto = ST(0);
    bn = BN_new();
    checkOpenSslCall( BN_sqr( bn, a, ctx ) );
    RETVAL = bn;
  OUTPUT:
    RETVAL

SV*
mod(a, b, ctx, ...)
    Crypt::OpenSSL::Bignum a;
    Crypt::OpenSSL::Bignum b;
    Crypt::OpenSSL::Bignum::CTX ctx;
  PREINIT:
    BIGNUM* bn;
  PPCODE:
    if( items > 4 )
      croak( "usage: $bn->add( $bn2, $ctx, [, $target] )" );
    bn = ( items < 4 ) ? BN_new() : sv2bn( ST(3) );
    checkOpenSslCall( BN_mod( bn, a, b, ctx ) );
    ST(0) = ( (items < 4 ) ? proto_obj( bn ) : ST(3) );
    XSRETURN(1);

Crypt::OpenSSL::Bignum
mod_mul(a, b, m, ctx)
    Crypt::OpenSSL::Bignum a;
    Crypt::OpenSSL::Bignum b;
    Crypt::OpenSSL::Bignum m;
    Crypt::OpenSSL::Bignum::CTX ctx;
  PREINIT:
    BIGNUM* bn;
    SV* p_proto;
  CODE:
    p_proto = ST(0);
    bn = BN_new();
    checkOpenSslCall( BN_mod_mul( bn, a, b, m, ctx ) );
    RETVAL = bn;
  OUTPUT:
    RETVAL

Crypt::OpenSSL::Bignum
exp(a, p, ctx)
    Crypt::OpenSSL::Bignum a;
    Crypt::OpenSSL::Bignum p;
    Crypt::OpenSSL::Bignum::CTX ctx;
  PREINIT:
    BIGNUM* bn;
    SV* p_proto;
  CODE:
    p_proto = ST(0);
    bn = BN_new();
    checkOpenSslCall( BN_exp( bn, a, p, ctx ) );
    RETVAL = bn;
  OUTPUT:
    RETVAL

Crypt::OpenSSL::Bignum
mod_exp(a, p, m, ctx)
    Crypt::OpenSSL::Bignum a;
    Crypt::OpenSSL::Bignum p;
    Crypt::OpenSSL::Bignum m;
    Crypt::OpenSSL::Bignum::CTX ctx;
  PREINIT:
    BIGNUM* bn;
    SV* p_proto;
  CODE:
    p_proto = ST(0);
    bn = BN_new();
    checkOpenSslCall( BN_mod_exp( bn, a, p, m, ctx ) );
    RETVAL = bn;
  OUTPUT:
    RETVAL

Crypt::OpenSSL::Bignum
mod_inverse(a, n, ctx)
    Crypt::OpenSSL::Bignum a;
    Crypt::OpenSSL::Bignum n;
    Crypt::OpenSSL::Bignum::CTX ctx;
  PREINIT:
    BIGNUM* bn;
    SV* p_proto;
  CODE:
    p_proto = ST(0);
    bn = BN_new();
    checkOpenSslCall( BN_mod_inverse( bn, a, n, ctx ) );
    RETVAL = bn;
  OUTPUT:
    RETVAL

Crypt::OpenSSL::Bignum
gcd(a, b, ctx)
    Crypt::OpenSSL::Bignum a;
    Crypt::OpenSSL::Bignum b;
    Crypt::OpenSSL::Bignum::CTX ctx;
  PREINIT:
    BIGNUM* bn;
    SV* p_proto;
  CODE:
    p_proto = ST(0);
    bn = BN_new();
    checkOpenSslCall( BN_gcd( bn, a, b, ctx ) );
    RETVAL = bn;
  OUTPUT:
    RETVAL

int
BN_cmp(a, b)
    Crypt::OpenSSL::Bignum a;
    Crypt::OpenSSL::Bignum b;

int
BN_is_zero(a)
    Crypt::OpenSSL::Bignum a;

int
BN_is_one(a)
    Crypt::OpenSSL::Bignum a;

int
BN_is_odd(a)
    Crypt::OpenSSL::Bignum a;

Crypt::OpenSSL::Bignum
copy(a)
    Crypt::OpenSSL::Bignum a;
  PREINIT:
    SV* p_proto;
  CODE:
    p_proto = ST(0);
    checkOpenSslCall( RETVAL = BN_dup(a) );
  OUTPUT:
    RETVAL

IV
pointer_copy(a)
    Crypt::OpenSSL::Bignum a;
  PREINIT:
  CODE:
    checkOpenSslCall( RETVAL = PTR2IV(BN_dup(a)) );
  OUTPUT:
    RETVAL

MODULE = Crypt::OpenSSL::Bignum  PACKAGE = Crypt::OpenSSL::Bignum::CTX

Crypt::OpenSSL::Bignum::CTX
new(CLASS)
    CODE:
        RETVAL = BN_CTX_new();
    OUTPUT:
        RETVAL

void
DESTROY(Crypt::OpenSSL::Bignum::CTX self)
    CODE:
        BN_CTX_free(self);
