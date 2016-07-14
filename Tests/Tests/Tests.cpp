// Tests.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdlib.h>
#include <stdlib.h>
#include <iostream>
#include <time.h>
#include <Windows.h>
#include "asn1funcs.h"
#include <WinCrypt.h>


template<class F, class A>
void Fwd(F f, A a)
{
    f(a);
}
 
void g(int* i)
{
    std::cout << "Function g called\n";
};


#define DEF_MAX_LEN		100

void func(int arr[DEF_MAX_LEN])
{

	for (int i=0; i<DEF_MAX_LEN; i++)
	{
		printf("%d\n", arr[i]);
	}

}



#define DEF_OBJECT_CLASS_DATA				0x0
#define DEF_OBJECT_CLASS_CERTIFICATE		0x1

#define DEF_OBJECT_COMMON_FLAGS

#define DEF_DATA_OBJECT_LABEL				"Direct Mode CoSign Graphical Signature"
#define DEF_DATA_OBJECT_LABEL_LEN			strlen(DEF_DATA_OBJECT_LABEL)

int LLObjectToPKCS11(char * objectName, unsigned char * objectData, unsigned long objectLen, unsigned char * PKCS11Object, int * PKCS11ObjectLen)
{
	int rc = 0;

	

	if (PKCS11Object == NULL)
	{

		// calc required length 
		// need 4 bytes for 
		int requiredLength = 4;

	}
	
	// set object class
	PKCS11Object[0] = DEF_OBJECT_CLASS_DATA;

	// set common flags
	PKCS11Object[1] |= 1;		// token 
	PKCS11Object[1] |= 1 << 1;	// private
	PKCS11Object[1] |= 1 << 2;	// modifiable
	PKCS11Object[1] |= 1 << 7;	// PKCS11 v2.11 format.

	// label length 
	PKCS11Object += 2;
	*((UINT16*)PKCS11Object) = DEF_DATA_OBJECT_LABEL_LEN;
	PKCS11Object += 2;

	// label
	strncpy_s((char*)PKCS11Object, DEF_DATA_OBJECT_LABEL_LEN, DEF_DATA_OBJECT_LABEL, _TRUNCATE);
	PKCS11Object += DEF_DATA_OBJECT_LABEL_LEN;

	// Application attr
	*((UINT16*)PKCS11Object) = 0;

	PKCS11Object += 2;

	// value 
	*((UINT16*)PKCS11Object) = objectLen;
	PKCS11Object += 2;

	memcpy_s(PKCS11Object,objectLen, objectData, objectLen);
	PKCS11Object += objectLen;

	// Internal major version
	PKCS11Object[0] = 1;
	PKCS11Object[1] = 1;
	PKCS11Object[2] = 4;

	PKCS11Object += 3;
	
	*((UINT16*)PKCS11Object) = strlen(objectName);
	PKCS11Object += 2;

	strncpy_s((char*)PKCS11Object, strlen(objectName), objectName, _TRUNCATE);

	return rc;

}


int getPublic(unsigned char *cert, long certLen, unsigned char* publicKey, long *publicKeyLen)
{
	PCCERT_CONTEXT		pCertContext;
	unsigned char		*pubKeyPtr = NULL;
	int					pubKeyLen = 0;


	pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
												cert,
												certLen);

	if (pCertContext) 
	{
		unsigned char *ptr = pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData;
		unsigned long len = pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData;

		GetRawPubKeyFromASN1PubKey(ptr, len, &pubKeyPtr, (int *)pubKeyLen);
		if (publicKey == NULL)
		{
			*publicKeyLen = pubKeyLen;
		}
		else
		{

			memcpy_s(publicKey, *publicKeyLen, pubKeyPtr, *publicKeyLen);
		}
	}



	if (pCertContext) CertFreeCertificateContext(pCertContext);


	return 0;
}



class Base
{
public:
	int i;

	Base()
	{
		this->i = 12;
	}
};

class Derived : public Base
{
public:
	int j;

	Derived()
	{
		this->j = 14;
	}
};



int _tmain(int argc, _TCHAR* argv[])
{
	PUBLICKEYSTRUC pubStruct;
	RSAPUBKEY rsaPubKey;


	WCHAR aaa[123] = {0};


	WCHAR *d=NULL;
	swprintf (aaa, 20 ,L"%s",d);













	unsigned char SAPIPubKey[276] = {0};

	pubStruct.bType = PUBLICKEYBLOB;
	pubStruct.bVersion = CUR_BLOB_VERSION;
	pubStruct.aiKeyAlg = CALG_RSA_SIGN;
	pubStruct.reserved = 0;


	memcpy(&rsaPubKey.magic, "RSA1", sizeof(DWORD));
	rsaPubKey.bitlen = 2048;
	rsaPubKey.pubexp = 0x010001;

	memcpy_s(SAPIPubKey, 276, &pubStruct, sizeof(PUBLICKEYSTRUC));
	memcpy_s(&(SAPIPubKey[sizeof(PUBLICKEYSTRUC)]), 276 - sizeof(PUBLICKEYSTRUC), &rsaPubKey, sizeof(RSAPUBKEY));

	SAPIPubKey[sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY)] = 12;



	unsigned char data[128] = "RSA1";

	DWORD aa;

	memcpy(&aa, "RSA1", 4);
	reverseBytes(data, 128);

	printf("done\n");

	return 0;
}


