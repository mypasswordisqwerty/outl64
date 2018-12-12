// stdafx.h: включаемый файл дл€ стандартных системных включаемых файлов
// или включаемых файлов дл€ конкретного проекта, которые часто используютс€,
// но не часто измен€ютс€

#pragma once

#ifndef STRICT
#define STRICT
#endif

#include "targetver.h"

#define _ATL_APARTMENT_THREADED

#define _ATL_NO_AUTOMATIC_NAMESPACE

#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS	// некоторые конструкторы CString будут €вными

#include <afxwin.h>
#include <afxext.h>
#include <afxole.h>
#include <afxodlgs.h>
#include <afxrich.h>
#include <afxhtml.h>
#include <afxcview.h>
#include <afxwinappex.h>
#include <afxframewndex.h>
#include <afxmdiframewndex.h>

#ifndef _AFX_NO_OLE_SUPPORT
#include <afxdisp.h>        // классы автоматизации MFC
#endif // _AFX_NO_OLE_SUPPORT

#include <comsvcs.h>

#define ATL_NO_ASSERT_ON_DESTROY_NONEXISTENT_WINDOW

#include "resource.h"
#include <atlbase.h>
#include <atlcom.h>
#include <atlctl.h>

#include <Wincrypt.h>

#include <MAPIDefS.h>
#include <MAPITags.h>
#include <MAPI.h> 
#include <MAPIX.h>
#include <Wabiab.h>
#include <TNEF.h>

#define USES_IID_IMessage
#include <MAPIGuid.h>
#include <MAPIUtil.h>
