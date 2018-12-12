

/* this ALWAYS GENERATED file contains the IIDs and CLSIDs */

/* link this file in with the server and any clients */


 /* File created by MIDL compiler version 7.00.0555 */
/* at Wed Jun 21 21:07:36 2017
 */
/* Compiler settings for Outl64FuzzLib.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 7.00.0555 
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#pragma warning( disable: 4049 )  /* more than 64k source lines */


#ifdef __cplusplus
extern "C"{
#endif 


#include <rpc.h>
#include <rpcndr.h>

#ifdef _MIDL_USE_GUIDDEF_

#ifndef INITGUID
#define INITGUID
#include <guiddef.h>
#undef INITGUID
#else
#include <guiddef.h>
#endif

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
        DEFINE_GUID(name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8)

#else // !_MIDL_USE_GUIDDEF_

#ifndef __IID_DEFINED__
#define __IID_DEFINED__

typedef struct _IID
{
    unsigned long x;
    unsigned short s1;
    unsigned short s2;
    unsigned char  c[8];
} IID;

#endif // __IID_DEFINED__

#ifndef CLSID_DEFINED
#define CLSID_DEFINED
typedef IID CLSID;
#endif // CLSID_DEFINED

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
        const type name = {l,w1,w2,{b1,b2,b3,b4,b5,b6,b7,b8}}

#endif !_MIDL_USE_GUIDDEF_

MIDL_DEFINE_GUID(IID, IID_IComponentRegistrar,0xa817e7a2,0x43fa,0x11d0,0x9e,0x44,0x00,0xaa,0x00,0xb6,0x77,0x0a);


MIDL_DEFINE_GUID(IID, IID_IMapiFuzz,0x7CEECFDA,0x32C6,0x4592,0xBE,0x27,0xA8,0x81,0xE1,0x96,0x7F,0xC4);


MIDL_DEFINE_GUID(IID, LIBID_Outl64FuzzLib,0xE8FBB04D,0x8A6F,0x4517,0xB6,0xEB,0x6F,0xC7,0x03,0x3D,0xF2,0xB5);


MIDL_DEFINE_GUID(CLSID, CLSID_CompReg,0x62E14862,0x97DC,0x47A7,0x92,0xBC,0x0B,0x19,0x08,0x27,0xAD,0xD8);


MIDL_DEFINE_GUID(IID, DIID__IMapiFuzzEvents,0x7CEECFDD,0x32C6,0x4592,0xBE,0x27,0xA8,0x81,0xE1,0x96,0x7F,0xC4);


MIDL_DEFINE_GUID(CLSID, CLSID_MapiFuzz,0x2FD04774,0x5788,0x4BBA,0xB9,0x25,0x71,0xAF,0xBC,0x0A,0x38,0xC7);

#undef MIDL_DEFINE_GUID

#ifdef __cplusplus
}
#endif



