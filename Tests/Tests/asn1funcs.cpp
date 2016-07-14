#include "stdafx.h"

#include <time.h>
#include <string.h>
#include "asn1def.h"

//#include "pkiglb.h"
//#include "asn1fun.h"
//#include "pkcs7sd.h"
//#include "moreasn1.h"

//#define LOWLEVEL_API
//
#ifndef BYTE
#define BYTE unsigned char
#endif
//
///* decode contents length octets */
void 
    asn1_get_len(unsigned char * bin_ptr,
                 int          * len,
                 int           * len_of_len)

{
    int         i;
    *len = 0;

    if (bin_ptr[0] == ASN1_LONG_LENGTH_FORM ) {
        *len_of_len = 0;
        *len = 0; 
    } else if (bin_ptr[0] & ASN1_LONG_LENGTH_FORM) {
        *len_of_len = bin_ptr[0] ^ ASN1_LONG_LENGTH_FORM;
        bin_ptr++;
        for (i=0;i<*len_of_len;i++) {
            *len *= 256;
            *len += bin_ptr++[0];
        }
    } else {
        *len_of_len = 0;
        *len = bin_ptr[0];
    }

    (*len_of_len)++;


} /* asn1_get_len */
//
//int LOWLEVEL_API asn1_get_date_from_time(
//                            unsigned char	*cert,
//							time_t			*out_time)
//
//{
//    struct tm			time_tm;
//    unsigned char		* orig_ptr = cert;
//    int					time_len;
//	int					len_of_len;
//
//    time_tm.tm_isdst = 0;
//	time_tm.tm_year = 0;
//
//
//    if ((cert[0] == ASN1_UTCTime) || (cert[0] == ASN1_GENTime))
//		cert++;
//
//    asn1_get_len(cert, &time_len, &len_of_len);
//    cert += len_of_len;
//    if (orig_ptr[0] != ASN1_UTCTime) {
//		time_tm.tm_year  = (cert[0]-ASCII_0) * 1000 +
//						   (cert[1]-ASCII_0) * 100;
//		cert += 2;
//	}
//
//    time_tm.tm_year  += ((cert[0]-ASCII_0) * 10) + (cert[1]-ASCII_0);
//    time_tm.tm_mon   = ((cert[2]-ASCII_0) * 10) + (cert[3]-ASCII_0) - 1;
//    time_tm.tm_mday  = ((cert[4]-ASCII_0) * 10) + (cert[5]-ASCII_0);
//    time_tm.tm_hour  = ((cert[6]-ASCII_0) * 10) + (cert[7]-ASCII_0);
//    time_tm.tm_min   = ((cert[8]-ASCII_0) * 10) + (cert[9]-ASCII_0);
//    cert += 10;
//    
//	if (orig_ptr[0] != ASN1_UTCTime)
//		time_tm.tm_year -= 1900;
//	else if (time_tm.tm_year < 50)
//        time_tm.tm_year += 100;
//
//    if ((cert[0] >= ASCII_0) && (cert[0] <= ASCII_9)) {
//        time_tm.tm_sec = ((cert[0]-ASCII_0) * 10) + (cert[1]-ASCII_0);
//        cert += 2;
//		if ((cert[0] == ASCII_DOT) || (cert[0] == ASCII_COMMA)) {
//			cert++;
//			while ((cert[0] >= ASCII_0) && (cert[0] <= ASCII_9))
//			    cert++;
//		}
//	} else
//        time_tm.tm_sec = 0;
//
//    if (cert[0] == ASCII_PLUS) {
//		cert++;
//        time_tm.tm_hour -= ((cert[0]-ASCII_0) * 10) + (cert[1]-ASCII_0);
//         cert += 2;
//       if (cert-orig_ptr == time_len + len_of_len) {
//			time_tm.tm_min  -= ((cert[0]-ASCII_0) * 10) + (cert[1]-ASCII_0);
//			cert += 2;
//	   }
//     } else if (cert[0] == ASCII_MIN) {
//		cert++;
//        time_tm.tm_hour += ((cert[0]-ASCII_0) * 10) + (cert[1]-ASCII_0);
//        cert += 2;
//        if (cert-orig_ptr == time_len + len_of_len) {
//			time_tm.tm_min  += ((cert[0]-ASCII_0) * 10) + (cert[1]-ASCII_0);
//			cert += 2;
//		}
//    } else if (cert[0] != ASCII_Z)
//        return -1;
//
//	*out_time = mktime(&time_tm);		
//
//    return 0;
//
//} 


#define CHECK_OVERFLOW if (cert >= end_cert) return 1;

int 
  GetDnameSN(BYTE * cert,					/* IN: asn.1 encoded certificate */
             int	certLen,				/* IN: length, in bytes, of cert */
			 BYTE **subjectDname,			/* OUT: pointer to start of subject dname */
			 int  *	subjectDnameLen,		/* OUT: length, in bytes, of subjectDname */
			 BYTE **issuerDname,			/* OUT: pointer to start of issuer dname */
			 int  * issuerDnameLen,			/* OUT: length, in bytes, of issuerDname */
			 BYTE **SN,						/* OUT: pointer to start of serial number */
			 int  * SNLen)					/* OUT: length, in bytes, of serial number */
{
	int		len;
	int		len_of_len;
	BYTE  * end_cert = cert + certLen;

	/* skip certificate header */
	asn1_get_len(++cert,&len,&len_of_len);
	cert += len_of_len;
	CHECK_OVERFLOW;

	/* skip tbs header */
	asn1_get_len(++cert,&len,&len_of_len);
	cert += len_of_len;
	CHECK_OVERFLOW;

	/* skip version,serial Number and signature alg */
	asn1_get_len(++cert,&len,&len_of_len);
	cert += len + len_of_len;
	CHECK_OVERFLOW;

	/* get SN */
	asn1_get_len(++cert,&len,&len_of_len);
	if (SN)
		*SN = cert+len_of_len;
	if (SNLen)
		*SNLen = len;
	cert += len + len_of_len;
	CHECK_OVERFLOW;

	/* skip signature alg */
	asn1_get_len(++cert,&len,&len_of_len);
	cert += len + len_of_len;
	CHECK_OVERFLOW;

	/* got to issuer Dname */
	if (issuerDname)
		*issuerDname = cert;
	/* get dname length */
	asn1_get_len(++cert,&len,&len_of_len);
	if (issuerDnameLen)
		*issuerDnameLen = len + len_of_len + 1;
	cert += len + len_of_len;
	CHECK_OVERFLOW;

	/* skip validity */
	asn1_get_len(++cert,&len,&len_of_len);
	cert += len + len_of_len;
	CHECK_OVERFLOW;

	/* got to subject Dname */
	if (subjectDname)
		*subjectDname = cert;
	/* get dname length */
	asn1_get_len(++cert,&len,&len_of_len);
	if (subjectDnameLen)
		*subjectDnameLen = len + len_of_len + 1;
	/* skip subject dname */
	cert += len + len_of_len;
	CHECK_OVERFLOW;

	return 0;
}

int 
  GetRawPubKeyFromASN1PubKey(BYTE * ASN1PubKey,					/* IN: asn.1 encoded certificate */
             int	ASN1PubKeyLen,				/* IN: length, in bytes, of cert */
			 BYTE **PubKey,						/* OUT: pointer to start of serial number */
			 int  * PubKeyLen)					/* OUT: length, in bytes, of serial number */
{
	int		len;
	int		len_of_len;

	/* skip header */
	asn1_get_len(++ASN1PubKey,&len,&len_of_len);
	ASN1PubKey += len_of_len;

	/* skip integer value*/
	ASN1PubKey++;

	/* skip the public key len */
	asn1_get_len(ASN1PubKey ,&len,&len_of_len);
	ASN1PubKey  += len_of_len;

	// if there is padding, skip one byte */
	if (len%2) {
		ASN1PubKey++; 
		len--;
	}

	*PubKey = ASN1PubKey;
	*PubKeyLen = len;
	
	return 0;
}

//int LOWLEVEL_API get_certificate_expiration_date(
//                                    BYTE	*cert,
//									int		certLen,
//									time_t	*expiration_date) 
//
//{
//	int		len;
//	int		len_of_len;
//	BYTE  * end_cert = cert + certLen;
//	int		rc;
//
//	/* skip certificate header */
//	asn1_get_len(++cert,&len,&len_of_len);
//	cert += len_of_len;
//	CHECK_OVERFLOW;
//
//	/* skip tbs header */
//	asn1_get_len(++cert,&len,&len_of_len);
//	cert += len_of_len;
//	CHECK_OVERFLOW;
//
//	/* skip version,serial Number and signature alg */
//	asn1_get_len(++cert,&len,&len_of_len);
//	cert += len + len_of_len;
//	CHECK_OVERFLOW;
//
//	/* skip SN */
//	asn1_get_len(++cert,&len,&len_of_len);
//	cert += len + len_of_len;
//	CHECK_OVERFLOW;
//
//	/* skip signature alg */
//	asn1_get_len(++cert,&len,&len_of_len);
//	cert += len + len_of_len;
//	CHECK_OVERFLOW;
//
//	/* skip the issuer Dname */
//	/* get dname length */
//	asn1_get_len(++cert,&len,&len_of_len);
//	cert += len + len_of_len;
//	CHECK_OVERFLOW;
//
//	/* get expiration date */
//	/* skip the validity len */
//	asn1_get_len(++cert,&len,&len_of_len);
//	cert += len_of_len;
//	CHECK_OVERFLOW;
//	/* get the start time len and skip it */
//	asn1_get_len(++cert,&len,&len_of_len);
//	cert += len + len_of_len;
//	CHECK_OVERFLOW;
//	/* now pointing at the expiration time, call the function that retrieves the time */
//	rc = asn1_get_date_from_time(cert,
//								 expiration_date);
//	return rc;
//}
//
//int LOWLEVEL_API get_certificate_validity_date(
//                                    BYTE	*cert,
//									int		certLen,
//									time_t	*validity_date) 
//
//{
//	int		len;
//	int		len_of_len;
//	BYTE  * end_cert = cert + certLen;
//	int		rc;
//
//	/* skip certificate header */
//	asn1_get_len(++cert,&len,&len_of_len);
//	cert += len_of_len;
//	CHECK_OVERFLOW;
//
//	/* skip tbs header */
//	asn1_get_len(++cert,&len,&len_of_len);
//	cert += len_of_len;
//	CHECK_OVERFLOW;
//
//	/* skip version,serial Number and signature alg */
//	asn1_get_len(++cert,&len,&len_of_len);
//	cert += len + len_of_len;
//	CHECK_OVERFLOW;
//
//	/* skip SN */
//	asn1_get_len(++cert,&len,&len_of_len);
//	cert += len + len_of_len;
//	CHECK_OVERFLOW;
//
//	/* skip signature alg */
//	asn1_get_len(++cert,&len,&len_of_len);
//	cert += len + len_of_len;
//	CHECK_OVERFLOW;
//
//	/* skip the issuer Dname */
//	/* get dname length */
//	asn1_get_len(++cert,&len,&len_of_len);
//	cert += len + len_of_len;
//	CHECK_OVERFLOW;
//
//	/* get expiration date */
//	/* skip the validity len */
//	asn1_get_len(++cert,&len,&len_of_len);
//	cert += len_of_len;
//	CHECK_OVERFLOW;
//	/* get the start time len and skip it */
////	asn1_get_len(++cert,&len,&len_of_len);
////	cert += len + len_of_len;
////	CHECK_OVERFLOW;
//	/* now pointing at the validity time, call the function that retrieves the time */
//	rc = asn1_get_date_from_time(cert,
//								 validity_date);
//	return rc;
//}
//
//void LOWLEVEL_API get_email_from_SN(
//                       unsigned char	*subject_dname,
//					   int				subject_dname_len,
//					   unsigned char	**mail,
//					   int				*mail_len,
//					   unsigned char	*mail_field_type)
//{
//	unsigned char	object_identifier[]		= {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
//											   0x01, 0x09, 0x01};
//	int				object_identifier_len	= sizeof(object_identifier);
//	int				i;
//
//	*mail		= NULL;
//	*mail_len	= 0;
//
//	for (i = 0 ; i <= subject_dname_len - object_identifier_len - 2 ; i++) {
//		if (memcmp(subject_dname + i, object_identifier, object_identifier_len) == 0) {
//			*mail				= subject_dname + i + object_identifier_len + 2;
//			*mail_len			= subject_dname[i + object_identifier_len + 1];
//			*mail_field_type	= subject_dname[i + object_identifier_len];
//			break;
//		}
//	}
//}
//
//void LOWLEVEL_API get_CN_from_SN(
//                    unsigned char	*subject_dname,
//				    int				subject_dname_len,
//					unsigned char	**CN,
//					int				*CN_len,
//				    unsigned char	*CN_field_type)
//{
//	unsigned char	object_identifier[]		= {0x06, 0x03, 0x55, 0x04, 0x03};
//	int				object_identifier_len	= sizeof(object_identifier);
//	int				i;
//
//	*CN		= NULL;
//	*CN_len	= 0;
//
//	for (i = 0 ; i <= subject_dname_len - object_identifier_len - 2 ; i++) {
//		if (memcmp(subject_dname + i, object_identifier, object_identifier_len) == 0) {
//			*CN				= subject_dname + i + object_identifier_len + 2;
//			*CN_len			= subject_dname[i + object_identifier_len + 1];
//			*CN_field_type	= subject_dname[i + object_identifier_len];
//			// Peleg wrote:I remove the break inorder to get the last cn(it seems to be the most importent) 
////			break;
//		}
//	}
//}
//
//int LOWLEVEL_API get_CN_from_cert(
//                    unsigned char	*cert_ptr,
//				    int				certificate_len,
//					unsigned char	**CN,
//					int				*CN_len,
//				    unsigned char	*CN_field_type)
//{
//    unsigned char	*subject_dname;
//	int				subject_dname_len;
////	unsigned char	object_identifier[]		= {0x06, 0x03, 0x55, 0x04, 0x03};
////	int				object_identifier_len	= sizeof(object_identifier);
//	int				rc;
//
//	rc = GetDnameSN(cert_ptr,
//					certificate_len,
//					&subject_dname,
//					&subject_dname_len,
//					NULL,
//					NULL,
//					NULL,
//					NULL);
//
//	if (rc == 0) {
//		get_CN_from_SN(subject_dname,
//					   subject_dname_len,
//					   CN,
//					   CN_len,
//					   CN_field_type);
//	}
//
//	return rc;
//
//}
//
//int LOWLEVEL_API get_issuer_from_cert(
//                    unsigned char	*cert_ptr,
//				    int				certificate_len,
//					unsigned char	**issuer,
//					int				*issuer_len,
//				    unsigned char	*issuer_field_type)
//{
//    unsigned char	*issuer_dname;
//	int				issuer_dname_len;
//	int				rc;
//
//	rc = GetDnameSN(cert_ptr,
//					certificate_len,
//					NULL,
//					NULL,
//					&issuer_dname,
//					&issuer_dname_len,
//					NULL,
//					NULL);
//
//	if (rc == 0) {
//		get_CN_from_SN(issuer_dname,
//					   issuer_dname_len,
//					   issuer,
//					   issuer_len,
//					   issuer_field_type);
//	}
//
//	return rc;
//
//}
//
//int LOWLEVEL_API get_email_from_cert(
//						unsigned char	*cert_ptr,
//						int				certificate_len,
//						unsigned char	**mail,
//						int				*mail_len,
//						unsigned char	*mail_field_type)
//{
//    unsigned char	*subject_dname;
//	int				subject_dname_len;
//	int				rc;
//
//	rc = GetDnameSN(cert_ptr,
//					certificate_len,
//					&subject_dname,
//					&subject_dname_len,
//					NULL,
//					NULL,
//					NULL,
//					NULL);
//
//	if (rc == 0) {
//		get_email_from_SN(subject_dname,
//						  subject_dname_len,
//						  mail,
//						  mail_len,
//						  mail_field_type);
//	}
//
//	return rc;
//}
/*
 * The following functions are used for signing hash functionality. Specifically they are used
 *  for building a PKCS7 block after the hash value was RSA decrypted.
 *  the definition of asn1_enc_content_info  can be found in pkcs7sd.h that is dated 25/2/02
 *  and the implementation that can be found here was copied from Uri's implementation for the 
 *  ADOBE roaming ID web services. I am not sure whether Uri was writing this code or copied it
 *  from one of the PKCS/ASN1 libs that we have in AR.  Tal, 08/01/2008
 */

/* encode content info */



/* encode digest algorithms */