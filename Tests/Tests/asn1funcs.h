#ifndef __ASN1FUNCS__
#define __ASN1FUNCS__

#include <time.h>

//#define LOWLEVEL_API
//
//#ifndef LOWLEVEL_API
//#define LOWLEVEL_API __declspec(dllimport)
//#endif

#define ASN1_PrintableString    0x13
#define ASN1_UniversalString	0x1c
#define ASN1_BMPString			0x1e
#define ASN1_UTF8STRING			0x0C

int  GetDnameSN(
             BYTE * cert,					/* IN: asn.1 encoded certificate */
			 int	certLen,				/* IN: length, in bytes, of cert */
			 BYTE **subjectDname,			/* OUT: pointer to start of subject dname */
			 int  *	subjectDnameLen,		/* OUT: length, in bytes, of subjectDname */
			 BYTE **issuerDname,			/* OUT: pointer to start of issuer dname */
			 int  * issuerDnameLen,			/* OUT: length, in bytes, of issuerDname */
			 BYTE **SN,						/* OUT: pointer to start of serial number */
			 int  * SNLen);					/* OUT: length, in bytes, of serial number */

int  GetRawPubKeyFromASN1PubKey(
				BYTE * ASN1PubKey,					/* IN: asn.1 encoded certificate */
				int	ASN1PubKeyLen,				/* IN: length, in bytes, of cert */
				BYTE **PubKey,						/* OUT: pointer to start of serial number */
				int  * PubKeyLen);					/* OUT: length, in bytes, of serial number */


//int LOWLEVEL_API get_certificate_expiration_date(
//                                    BYTE	*cert,
//									int		certLen,
//									time_t	*expiration_date);
//
//int LOWLEVEL_API get_certificate_validity_date(
//                                    BYTE	*cert,
//									int		certLen,
//									time_t	*expiration_date);
//
//void LOWLEVEL_API get_email_from_SN(
//                       unsigned char	*subject_dname,
//					   int				subject_dname_len,
//					   unsigned char	**mail,
//					   int				*mail_len,
//					   unsigned char	*mail_field_type);
//
//void LOWLEVEL_API get_CN_from_SN(
//                    unsigned char	*subject_dname,
//				    int				subject_dname_len,
//					unsigned char	**CN,
//					int				*CN_len,
//				    unsigned char	*CN_field_type);
//
//int LOWLEVEL_API get_CN_from_cert(
//                    unsigned char	*cert_ptr,
//				    int				certificate_len,
//					unsigned char	**CN,
//					int				*CN_len,
//				    unsigned char	*CN_field_type);
//
//int LOWLEVEL_API get_email_from_cert(
//						unsigned char	*cert_ptr,
//						int				certificate_len,
//						unsigned char	**mail,
//						int				*mail_len,
//						unsigned char	*mail_field_type);
//
//int LOWLEVEL_API get_issuer_from_cert(
//                    unsigned char	*cert_ptr,
//				    int				certificate_len,
//					unsigned char	**issuer,
//					int				*issuer_len,
//				    unsigned char	*issuer_field_type);



#endif


