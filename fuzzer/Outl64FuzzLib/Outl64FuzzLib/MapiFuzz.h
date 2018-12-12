// MapiFuzz.h: объ€вление CMapiFuzz

#pragma once
#include "Outl64FuzzLib_i.h"
#include "resource.h"       // основные символы
#include <comsvcs.h>
#include "_IMapiFuzzEvents_CP.H"
#include "ILog.h"

using namespace ATL;

#define LOG_PROXY(level) va_list lst; va_start(lst,msg); _log(level,msg,lst); va_end(lst) 

// CMapiFuzz
struct SPropValueArray {
	ULONG cValues;
	SPropValue values[1];
};


class ATL_NO_VTABLE CMapiFuzz :
	public CComObjectRootEx<CComSingleThreadModel>,
	public CComCoClass<CMapiFuzz, &CLSID_MapiFuzz>,
	public ILog,
	public IConnectionPointContainerImpl<CMapiFuzz>,
	public IConnectionPointImpl<CMapiFuzz, &DIID__IMapiFuzzEvents>,
	public IDispatchImpl<IMapiFuzz, &IID_IMapiFuzz, &LIBID_Outl64FuzzLib, /*wMajor =*/ 1, /*wMinor =*/ 0>,
	public CProxy_IMapiFuzzEvents<CMapiFuzz>
{
public:
	CMapiFuzz() {};

	DECLARE_PROTECT_FINAL_CONSTRUCT()

	HRESULT FinalConstruct();

	void FinalRelease();

DECLARE_REGISTRY_RESOURCEID(IDR_MAPIFUZZ)

DECLARE_NOT_AGGREGATABLE(CMapiFuzz)

BEGIN_COM_MAP(CMapiFuzz)
	COM_INTERFACE_ENTRY(IMapiFuzz)
	COM_INTERFACE_ENTRY(IDispatch)
	COM_INTERFACE_ENTRY(IConnectionPointContainer)
END_COM_MAP()

BEGIN_CONNECTION_POINT_MAP(CMapiFuzz)
	CONNECTION_POINT_ENTRY(__uuidof(_IMapiFuzzEvents))
END_CONNECTION_POINT_MAP()

private:
	int logLevel;

	void _log(int level, CString &msg, va_list lst);
	virtual void debug(CString msg, ...) { LOG_PROXY(LOG_DEBUG); }
	virtual void info(CString msg, ...) { LOG_PROXY(LOG_INFO); }
	virtual void warning(CString msg, ...) { LOG_PROXY(LOG_WARNING); }
	virtual void error(CString msg, ...) { LOG_PROXY(LOG_ERROR); }
	BOOL parseTnefStream(IStream* stream, IMessage* msg);
	IStream* getVariantStream(VARIANT *var, int idx);
	BOOL setMessageProps(IMessage* msg, IStream* stream);	
	BOOL parseCertStream(IStream* stream);

// IMapiFuzz
public:
	STDMETHOD(version)(BSTR* result);
	/*
	*	data - variant with stream(s) for parsing:
	*	IUnknown - IStream
	*	bstr - filename
	*   array<byte> - stream data
	*	array<IUnknown> - IStream items
	*	array<bstr> - files
	*/
	STDMETHOD(parseTnef)(VARIANT data, LONG mockMessage, LONG* processed);

	STDMETHOD(config)(LONG logLevel);
	/*
	 *	propValues - {ULONG cValues; SPropValue values[]} file
	 */
	STDMETHOD(createMessage)(VARIANT propValues, LONG* processed);
	STDMETHOD(parseCert)(VARIANT propValues, LONG* processed);

	STDMETHOD(crash)(LONG param);

};

OBJECT_ENTRY_AUTO(__uuidof(MapiFuzz), CMapiFuzz)
