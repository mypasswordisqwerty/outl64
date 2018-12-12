// MapiFuzz.cpp: реализация CMapiFuzz

#include "stdafx.h"
#include "MapiFuzz.h"
#include "MessageMock.h"
#include "Util.h"
#include "mimeole.h"
#include "MailBuilder.h"
// CMapiFuzz

HRESULT CMapiFuzz::FinalConstruct()
{
	logLevel = LOG_ERROR;
	return Util::get().initialize(this);
}

void CMapiFuzz::FinalRelease()
{
	Util::get().finalize();
}

STDMETHODIMP CMapiFuzz::version(BSTR* result)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	debug(L"version method called");
#ifdef _WIN64
	*result = CComBSTR(L"MapiFuzz 64bit");
#else
	*result = CComBSTR(L"MapiFuzz 32bit");
#endif
	return S_OK;
}

IStream* CMapiFuzz::getVariantStream(VARIANT *var, int idx)
{
	bool isArr = (var->vt & VT_ARRAY) != 0;
	IStream* res = nullptr;
	if (idx > 0 && !isArr) {
		return nullptr;
	}

	switch (var->vt) {
	case VT_UNKNOWN: {
		var->punkVal->QueryInterface(IID_IStream, (void**)&res);
		break;
	}

	case VT_BSTR:
	case VT_BSTR | VT_BYREF: {
		CComBSTR s(var->vt == VT_BSTR ? var->bstrVal : *var->pbstrVal);
		debug(L"creating from file %ls", s);
		HRESULT hr = SHCreateStreamOnFileEx(s, STGM_READ | STGM_SHARE_DENY_NONE, 0, FALSE, NULL, &res);
		if (!SUCCEEDED(hr)) {
			error(L"Cant create filestream: 0x%X", hr);
			break;
		}
		break;
	}

	case VT_VARIANT:
	case VT_VARIANT | VT_BYREF:
		return getVariantStream(var->pvarVal, 0);

	default:
		if (!isArr) {
			break;
		}
		COleSafeArray arr(var);
		LONG lBound = 0;
		LONG bound = 0;
		arr.GetLBound(1, &lBound);
		arr.GetUBound(1, &bound);
		LONG sz = bound - lBound;
		bound = lBound + idx;
		if (idx >= sz) {
			break;
		}
		if (arr.GetElemSize()==1) {
			if (idx > 0) {
				break;
			}
			debug(L"creating from byte array");
			CreateStreamOnHGlobal(NULL, true, &res);
			if (res) {
				CByteArray data;
				arr.GetByteArray(data);
				res->Write(data.GetData(), (ULONG)data.GetCount(), NULL);
			}
			break;
		}
		VARIANT v;
		arr.GetElement(&bound, &v);
		return getVariantStream(&v, 0);
	}
	return res;
}


STDMETHODIMP CMapiFuzz::config(LONG logLevel)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	this->logLevel = logLevel;
	return S_OK;
}

void CMapiFuzz::_log(int level, CString &msg, va_list lst)
{
	if (level < logLevel) {
		return;
	}
	CString log;
	log.FormatV(msg, lst);
	Fire_log(level, CComBSTR(log));
}


BOOL CMapiFuzz::parseTnefStream(IStream * stream, IMessage* msg)
{
	Util::get().rewindStream(stream);

	ITnef *tnef = nullptr;
	HRESULT hr = OpenTnefStreamEx(NULL, stream, L"winmail.dat", TNEF_DECODE, msg, 0xDEAD, Util::get().abook, &tnef);
	if (!SUCCEEDED(hr)) {
		error(L"Error creating tnef: 0x%X", hr);
		return FALSE;
	}
	SizedSPropTagArray(103, arr) = { 103, { 0x150040, 0x170003, 0x23000B, 0x220102, 0x240102, 0x300040, 0x360003, 0x37001E, 0x390040, 0x3B0102, 0x3D001F, 0x3F0102, 0x40001E, 0x410102, 0x42001E, 0x430102, 0x44001E, 0x460102, 0x4F0102, 0x50001E, 0x510102, 0x520102, 0x57000B, 0x58000B, 0x59000B, 0x64001E, 0x65001E, 0x75001E, 0x76001E, 0x77001E, 0x78001E, 0x7D001E, 0x83101F, 0x84101F, 0x85001F, 0xC090102, 0xC190102, 0xC1A001E, 0xC1D0102, 0xC1E001E, 0xC1F001E, 0xE02001E, 0xE03001E, 0xE04001E, 0xE05001E, 0xE070003, 0xE060040, 0xE080003, 0xE090102, 0xE12000D, 0xE1B000B, 0xE1D001E, 0xE2B0003, 0xE2C0102, 0xE2D0102, 0xE9C0102, 0xFF40003, 0xFF70003, 0xFF90102, 0xFFB0102, 0xFFF0102, 0x1000001E, 0x10020102, 0x10130102, 0x1030001F, 0x1031001F, 0x1032001F, 0x1033001E, 0x10340003, 0x1035001E, 0x1037001E, 0x1038001E, 0x1039001E, 0x1042001F, 0x1043001F, 0x1044001F, 0x1045001F, 0x10800003, 0x10900003, 0x10910040, 0x10950003, 0x10960003, 0x3004001E, 0x30070040, 0x30080040, 0x300B0102, 0x40760003, 0x4083001F, 0x6E010003, 0x0001, 0x801F001F, 0x80360003, 0x804C001E, 0x800D001E, 0x800E001E, 0x80AA0040, 0x80AB001F, 0x80AC001F, 0x80400003, 0x80BA0040, 0x80410003, 0x80420003, 0x80BF001F } };
	//0x60002011 >> 
	hr = tnef->ExtractProps(0x182, (LPSPropTagArray)&arr, NULL);
	if (!SUCCEEDED(hr)) {
		error(L"Error parsing tnef: 0x%X", hr);
	}
	tnef->Release();
	return TRUE;
}


STDMETHODIMP CMapiFuzz::parseTnef(VARIANT data, LONG mockMessage, LONG* processed)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	debug(L"parseTnef method called");
	LONG proc = 0;
	int idx = 0;
	IStream* stream=getVariantStream(&data, idx++);
	if (!stream) {
		return E_INVALIDARG;
	}
	MessageMock msg(this);
	IMessage* imsg = mockMessage ? &msg : Util::get().createMessage();
	if (!imsg) {
		imsg = &msg;
	}
	while (stream) {
		proc += parseTnefStream(stream, imsg);
		stream->Release();
		stream = getVariantStream(&data, idx++);
	}
	imsg->Release();
	if (processed) {
		*processed = proc;
	}
	return S_OK;
}

BOOL CMapiFuzz::setMessageProps(IMessage* msg, IStream* stream) {
	ULONG bsz=Util::get().rewindStream(stream);
	void* buf=nullptr;
	MAPIAllocateBuffer(bsz,&buf);
	stream->Read(buf, bsz, &bsz);
	SPropValueArray *v = (SPropValueArray *)buf;
	HRESULT hr = msg->SetProps(v->cValues, (LPSPropValue)&v->values, NULL);
	if (!SUCCEEDED(hr)) {
		error(L"Error setting props: 0x%X", hr);
	}
	MAPIFreeBuffer(buf);
	return TRUE;
}


STDMETHODIMP CMapiFuzz::createMessage(VARIANT propValues, LONG* processed)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	debug(L"createMessage method called");
	int idx = 0;
	LONG proc = 0;
	IStream* stream = getVariantStream(&propValues, idx++);
	if (!stream) {
		return E_INVALIDARG;
	}
	IMessage* msg = Util::get().createMessage();
	if (!msg) {
		error(L"Message not created.");
		return E_ABORT;
	}
	while (stream){
		proc += setMessageProps(msg, stream);
		stream->Release();
		stream = getVariantStream(&propValues, idx++);
	}
	msg->Release();
	if (processed) {
		*processed = proc;
	}
	return S_OK;
}


BOOL CMapiFuzz::parseCertStream(IStream* stream) {
	IMimeSecurity* sec = NULL;
	IMimeMessage* msg = NULL;
	HRESULT hr = 0;
	MimeOleCreateMessageFunc mocm= Util::get().getMimeOleCreateMessage();
	hr = mocm(NULL, &msg);
	if (!SUCCEEDED(hr)) {
		error(L"Error creating message: 0x%X", hr);
		return FALSE;
	}
	MimeOleCreateSecurityFunc mocs = Util::get().getMimeOleCreateSecurity();
	hr = mocs(&sec);
	if (!SUCCEEDED(hr)) {
		error(L"Error creating security: 0x%X", hr);
		msg->Release();
		return FALSE;
	}
	MailBuilder bld(true);
	bld.setLog(this);
	CComPtr<IStream> mail = bld.mailForCert(stream);
	hr = msg->Load(mail);
	if (hr != S_OK) {
		error(L"Message Load failed: 0x%X", hr);
	}
	hr=sec->DecodeMessage(msg, 0);
	sec->Release();
	msg->Release();
	if (hr != S_OK) {
		error(L"DecodeMessage failed: 0x%X", hr);
		return FALSE;
	}
	return TRUE;
}


STDMETHODIMP CMapiFuzz::parseCert(VARIANT pkcs, LONG* processed)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	debug(L"parseCert method called");
	int idx = 0;
	LONG proc = 0;
	IStream* stream = getVariantStream(&pkcs, idx++);
	if (!stream) {
		return E_INVALIDARG;
	}
	while (stream) {
		proc += parseCertStream(stream);
		stream->Release();
		stream = getVariantStream(&pkcs, idx++);
	}
	if (processed) {
		*processed = proc;
	}
	return S_OK;
}

STDMETHODIMP CMapiFuzz::crash(LONG param)
{
	IMessage* msg = NULL;
	msg->AddRef();
	return S_OK;
}
