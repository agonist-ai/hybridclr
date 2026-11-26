#pragma once

#include <stdint.h>
#include "CommonDef.h"

namespace hybridclr
{
	class RuntimeApi
	{
	public:
		static void RegisterInternalCalls();

		static int32_t LoadMetadataForAOTAssembly(Il2CppArray* dllData, int32_t mode);

		static int32_t GetRuntimeOption(int32_t optionId);
		static void SetRuntimeOption(int32_t optionId, int32_t value);

		static int32_t PreJitClass(Il2CppReflectionType* type);
		static int32_t PreJitMethod(Il2CppReflectionMethod* method);

		// load gate (LoadGate.h)
		static int32_t GetLoadGate();
		static int32_t SetLoadGate(int32_t mode);
		static bool AllowLoad(Il2CppArray* sha256);
		static int32_t GetLoadGateCount(bool refused);
	};
}