#pragma once

#define LOG_DEBUG	0
#define LOG_INFO	1
#define LOG_WARNING	2
#define LOG_ERROR	3

#define FLOG_OK log->debug(L"call %hs",__FUNCTION__); return S_OK
#define FLOG_NOTIMPL log->debug(L"call %hs",__FUNCTION__); return E_NOTIMPL

class ILog
{
public:
	virtual void debug(CString msg, ...) =0;
	virtual void info(CString msg, ...) =0;
	virtual void warning(CString msg, ...) =0;
	virtual void error(CString msg, ...) =0;
};
