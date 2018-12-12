// dllmain.h: объ€вление класса модул€.

class COutl64FuzzLibModule : public ATL::CAtlDllModuleT< COutl64FuzzLibModule >
{
public :
	DECLARE_LIBID(LIBID_Outl64FuzzLib)
	DECLARE_REGISTRY_APPID_RESOURCEID(IDR_OUTL64FUZZLIB, "{696D5C18-EE59-4E68-B147-351B01BFA089}")
};

extern class COutl64FuzzLibModule _AtlModule;
