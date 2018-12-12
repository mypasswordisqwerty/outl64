#include "stdafx.h"
#include "MessageMock.h"

MessageMock::MessageMock(ILog* log)
{
	this->log = log;
}


MessageMock::~MessageMock()
{
}

HRESULT MessageMock::QueryInterface(const IID &riid, LPVOID *ppvObj)
{
	wchar_t siid[1024];
	StringFromGUID2(riid, siid, 1024);
	log->debug(L"Imsg queryintf %ls", siid);
	*ppvObj = this;
	return S_OK;
}

ULONG MessageMock::AddRef()
{
	FLOG_OK;
}

ULONG MessageMock::Release()
{
	FLOG_OK;
}

HRESULT MessageMock::GetLastError(HRESULT hResult, ULONG ulFlags, LPMAPIERROR *lppMAPIError)
{
	FLOG_NOTIMPL;
}

HRESULT MessageMock::SaveChanges(ULONG ulFlags)
{
	FLOG_NOTIMPL;
}

HRESULT MessageMock::GetProps(LPSPropTagArray lpPropTagArray, ULONG ulFlags, ULONG *lpcValues, LPSPropValue *lppPropArray)
{
	FLOG_NOTIMPL;
}

HRESULT MessageMock::GetPropList(ULONG ulFlags, LPSPropTagArray *lppPropTagArray)
{
	FLOG_NOTIMPL;
}

HRESULT MessageMock::OpenProperty(ULONG ulPropTag, LPCIID lpiid, ULONG ulInterfaceOptions, ULONG ulFlags, LPUNKNOWN *lppUnk)
{
	FLOG_NOTIMPL;
}

HRESULT MessageMock::SetProps(ULONG cValues, LPSPropValue lpPropArray, LPSPropProblemArray *lppProblems)
{
	log->debug(L"Imsg setting %d props:", cValues);
	for (UINT i = 0; i < cValues; i++) {
		SPropValue &p = lpPropArray[i];
		ULONG tag = p.ulPropTag;
		log->debug(L"%d IMsg property 0x%X or type 0x%X", i, PROP_ID(tag),PROP_TYPE(tag));
	}
	return S_OK;
}

HRESULT MessageMock::DeleteProps(LPSPropTagArray lpPropTagArray, LPSPropProblemArray *lppProblems)
{
	FLOG_NOTIMPL;
}

HRESULT MessageMock::CopyTo(ULONG ciidExclude, LPCIID rgiidExclude, LPSPropTagArray lpExcludeProps, ULONG ulUIParam, LPMAPIPROGRESS lpProgress, LPCIID lpInterface, LPVOID lpDestObj, ULONG ulFlags, LPSPropProblemArray *lppProblems)
{
	FLOG_NOTIMPL;
}

HRESULT MessageMock::CopyProps(LPSPropTagArray lpIncludeProps, ULONG ulUIParam, LPMAPIPROGRESS lpProgress, LPCIID lpInterface, LPVOID lpDestObj, ULONG ulFlags, LPSPropProblemArray *lppProblems)
{
	FLOG_NOTIMPL;
}

HRESULT MessageMock::GetNamesFromIDs(LPSPropTagArray *lppPropTags, LPGUID lpPropSetGuid, ULONG ulFlags, ULONG *lpcPropNames, LPMAPINAMEID **lpppPropNames)
{
	FLOG_NOTIMPL;
}

HRESULT MessageMock::GetIDsFromNames(ULONG cPropNames, LPMAPINAMEID *lppPropNames, ULONG ulFlags, LPSPropTagArray *lppPropTags)
{
	FLOG_NOTIMPL;
}

HRESULT MessageMock::GetAttachmentTable(ULONG ulFlags, LPMAPITABLE *lppTable)
{
	FLOG_OK;
}

HRESULT MessageMock::OpenAttach(ULONG ulAttachmentNum, LPCIID lpInterface, ULONG ulFlags, LPATTACH *lppAttach)
{
	FLOG_NOTIMPL;
}

HRESULT MessageMock::CreateAttach(LPCIID lpInterface, ULONG ulFlags, ULONG *lpulAttachmentNum, LPATTACH *lppAttach)
{
	FLOG_NOTIMPL;
}

HRESULT MessageMock::DeleteAttach(ULONG ulAttachmentNum, ULONG ulUIParam, LPMAPIPROGRESS lpProgress, ULONG ulFlags)
{
	FLOG_OK;
}

HRESULT MessageMock::GetRecipientTable(ULONG ulFlags, LPMAPITABLE *lppTable)
{
	FLOG_OK;
}

HRESULT MessageMock::ModifyRecipients(ULONG ulFlags, LPADRLIST lpMods)
{
	FLOG_OK;
}

HRESULT MessageMock::SubmitMessage(ULONG ulFlags)
{
	FLOG_OK;
}

HRESULT MessageMock::SetReadFlag(ULONG ulFlags)
{
	FLOG_OK;
}
