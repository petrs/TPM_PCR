/*++
Simple utility to collect the TPM information and TPM PCR registry. Heavily based on Microsoft PCPTool
2018, Petr Svenda, https://github.petrs
--*/
/*++
THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

Copyright (c) Microsoft Corporation.  All rights reserved.

Module Name:

SDKSample.cpp

Abstract:

This file contains the actual SDK samples for the Platform Crypto Provider.
--*/

#include "stdafx.h"

#define TPM_PCR_VERSION L"0.1.0"


#define TPM_AVAILABLE_PLATFORM_PCRS (24)
#define SHA1_DIGEST_SIZE   (20)
#define SHA256_DIGEST_SIZE (32)
#define MAX_DIGEST_SIZE    (64)
// TPM info location
#define TPM_STATIC_CONFIG_DATA L"System\\CurrentControlSet\\services\\TPM"
#define TPM_STATIC_CONFIG_QUOTE_KEYS L"SYSTEM\\CurrentControlSet\\Services\\Tpm\\PlatformQuoteKeys"
#define TPM_STATIC_CONFIG_KEYATTEST_KEYS L"SYSTEM\\CurrentControlSet\\Services\\Tpm\\KeyAttestationKeys"
#define TPM_VOLATILE_CONFIG_DATA L"System\\CurrentControlSet\\Control\\IntegrityServices"

const int MAX_LOG_MESSAGE_LENGTH = 1000;
const int MAX_FILE_NAME = 1000;
WCHAR fileName[MAX_FILE_NAME]; // file name for measurement storage
WCHAR deviceIDFileName[MAX_FILE_NAME]; // file name for unique device ID
FILE * pFile = NULL; // Used inside all functions if not null

void logResult(const WCHAR* message) {
	wprintf(message);
	if (pFile) fwprintf(pFile, message);
}
void logResult(const CHAR* message) {
	printf(message);
	if (pFile) fprintf(pFile, message);
}

void
PcpToolLevelPrefix(
	UINT32 level
	)
{
	for (UINT32 n = 0; n < level; n++)
	{
		logResult(L"  ");
	}
}


void
PcpToolCallResult(
	_In_ WCHAR* func,
	HRESULT hr
	)
{
	PWSTR Buffer = NULL;
	DWORD result = 0;
	WCHAR message[MAX_LOG_MESSAGE_LENGTH]; 

	if (FAILED(hr))
	{
		result = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			(PVOID)GetModuleHandle(NULL),
			hr,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
			(PTSTR)&Buffer,
			0,
			NULL);

		if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"<Error_%s>\n", func) >= 0) {
			logResult(message);
		}

		if (result != 0)
		{
			if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"%s: (0x%08lx) %s", func, hr, Buffer) >= 0) {
				logResult(message);
			}
		}
		else
		{
			if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"%s: (0x%08lx)\n", func, hr) >= 0) {
				logResult(message);
			}
		}
		if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"</Error_%s>\n", func) >= 0) {
			logResult(message);
		}
		LocalFree(Buffer);
	}
}

HRESULT
PcpToolGetPCRs()
{
	HRESULT hr = S_OK;
	PCWSTR fileName = NULL;
	NCRYPT_PROV_HANDLE hProv = NULL;
	BYTE pcrTable[TPM_AVAILABLE_PLATFORM_PCRS * MAX_DIGEST_SIZE] = { 0 };
	DWORD cbPcrTable = sizeof(pcrTable);
	DWORD digestSize = SHA1_DIGEST_SIZE;
	WCHAR message[MAX_LOG_MESSAGE_LENGTH];

	if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
		&hProv,
		MS_PLATFORM_CRYPTO_PROVIDER,
		0))))
	{
		goto Cleanup;
	}

	if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(hProv,
		NCRYPT_PCP_PCRTABLE_PROPERTY,
		pcrTable,
		sizeof(pcrTable),
		&cbPcrTable,
		0))))
	{
		goto Cleanup;
	}

	if ((cbPcrTable / TPM_AVAILABLE_PLATFORM_PCRS) == SHA256_DIGEST_SIZE)
	{
		digestSize = SHA256_DIGEST_SIZE;
	}

	logResult(L"<PCRs>\n");
	for (UINT32 n = 0; n < TPM_AVAILABLE_PLATFORM_PCRS; n++)
	{
		PcpToolLevelPrefix(1);
		if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"<PCR Index=\"%02u\">", n) >= 0) {
			logResult(message);
		}
		for (UINT32 m = 0; m < digestSize; m++)
		{
			if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"%02x", pcrTable[n * digestSize + m]) >= 0) {
				logResult(message);
			}
		}
		logResult(L"</PCR>\n");
	}
	logResult(L"</PCRs>\n");

Cleanup:
	if (hProv != NULL)
	{
		NCryptFreeObject(hProv);
		hProv = NULL;
	}
	PcpToolCallResult(L"PcpToolGetPCRs", hr);
	return hr;
}

HRESULT
PcpToolGetVersion()
	/*++
	Retrieve the version strings from the PCP provider and the TPM.
	--*/
{
	HRESULT hr = S_OK;
	NCRYPT_PROV_HANDLE hProvTpm = NULL;
	WCHAR versionData[256] = L"";
	DWORD cbData = 0;
	WCHAR message[MAX_LOG_MESSAGE_LENGTH];

	ZeroMemory(versionData, sizeof(versionData));

	if (FAILED(hr = HRESULT_FROM_NT(NCryptOpenStorageProvider(
		&hProvTpm,
		MS_PLATFORM_KEY_STORAGE_PROVIDER,
		NCRYPT_IGNORE_DEVICE_STATE_FLAG))))
	{
		goto Cleanup;
	}

	if (FAILED(hr = HRESULT_FROM_NT(NCryptGetProperty(
		hProvTpm,
		BCRYPT_PCP_PROVIDER_VERSION_PROPERTY,
		(PUCHAR)versionData,
		sizeof(versionData) - sizeof(WCHAR),
		&cbData,
		0))))
	{
		goto Cleanup;
	}

	if (cbData > sizeof(versionData) - sizeof(WCHAR))
	{
		hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		goto Cleanup;
	}
	versionData[cbData / sizeof(WCHAR)] = 0x0000;

	logResult(L"<Version>\n");
	if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"  <Provider>%s</Provider>\n", versionData) >= 0) {
		logResult(message);
	}
	if (FAILED(hr = HRESULT_FROM_NT(NCryptGetProperty(
		hProvTpm,
		BCRYPT_PCP_PLATFORM_TYPE_PROPERTY,
		(PUCHAR)versionData,
		sizeof(versionData) - sizeof(WCHAR),
		&cbData,
		0))))
	{
		goto Cleanup;
	}

	if (cbData > sizeof(versionData) - sizeof(WCHAR))
	{
		hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		goto Cleanup;
	}
	versionData[cbData / sizeof(WCHAR)] = 0x0000;

	if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"  <TPM>\n    %s\n  </TPM>\n", versionData) >= 0) {
		logResult(message);
	}
	logResult(L"</Version>\n");

Cleanup:
	if (hProvTpm != NULL)
	{
		NCryptFreeObject(hProvTpm);
		hProvTpm = NULL;
	}
	PcpToolCallResult(L"PcpToolGetVersion", hr);
	return hr;
}

/*++

Routine Description:

Read and return all platform counters

Arguments:

pOsBootCount - OS Boot counter - insecure index for log files.

pOsResumeCount - OS Resume counter - insecure index for log files.

pCurrentTpmBootCount - TPM 2.0 backed counter, not available on 1.2.

pCurrentTpmEventCount - TPM backed monotonic counter.

pCurrentTpmCounterId - Counter ID on 1.2 TPMs.

pInitialTpmBootCount - TPM 2.0 backed counter, not available on 1.2 when the platform was booted.

pInitialTpmEventCount - TPM backed monotonic counter when the platform was booted.

pInitialTpmCounterId - Counter ID on 1.2 TPMs when the platform was booted.

Return value:

S_OK - Success.

E_INVALIDARG - Parameter error.

E_FAIL - Internal consistency error.

Others as propagated by called functions.

--*/
HRESULT
TpmAttGetPlatformCounters(
	_Out_opt_ PUINT32 pOsBootCount,
	_Out_opt_ PUINT32 pOsResumeCount,
	_Out_opt_ PUINT64 pCurrentTpmBootCount,
	_Out_opt_ PUINT64 pCurrentTpmEventCount,
	_Out_opt_ PUINT64 pCurrentTpmCounterId,
	_Out_opt_ PUINT64 pInitialTpmBootCount,
	_Out_opt_ PUINT64 pInitialTpmEventCount,
	_Out_opt_ PUINT64 pInitialTpmCounterId)
{
	HRESULT hr = S_OK;
	DWORD cbData = 0;

	if (pOsBootCount != NULL)
	{
		// Obtain the current OSBootCount
		cbData = sizeof(UINT32);
		if (FAILED(hr = HRESULT_FROM_WIN32(RegGetValueW(
			HKEY_LOCAL_MACHINE,
			TPM_STATIC_CONFIG_DATA,
			L"OsBootCount",
			RRF_RT_REG_DWORD,
			NULL,
			(PBYTE)pOsBootCount,
			&cbData))))
		{
			goto Cleanup;
		}
	}

	if (pOsResumeCount != NULL)
	{
		// Obtain the current OSResumeCount
		cbData = sizeof(UINT32);
		if (FAILED(hr = HRESULT_FROM_WIN32(RegGetValueW(
			HKEY_LOCAL_MACHINE,
			TPM_VOLATILE_CONFIG_DATA,
			L"OsResumeCount",
			RRF_RT_REG_DWORD,
			NULL,
			(PBYTE)pOsResumeCount,
			&cbData))))
		{
			goto Cleanup;
		}
	}

	if (pCurrentTpmBootCount != NULL)
	{
		// Obtain the current BootCount
		cbData = sizeof(UINT64);
		if (FAILED(hr = HRESULT_FROM_WIN32(RegGetValueW(
			HKEY_LOCAL_MACHINE,
			TPM_VOLATILE_CONFIG_DATA,
			L"BootCount",
			RRF_RT_REG_QWORD,
			NULL,
			(PBYTE)pCurrentTpmBootCount,
			&cbData))))
		{
			goto Cleanup;
		}
	}

	if (pCurrentTpmEventCount != NULL)
	{
		// Obtain the current EventCount
		cbData = sizeof(UINT64);
		if (FAILED(hr = HRESULT_FROM_WIN32(RegGetValueW(
			HKEY_LOCAL_MACHINE,
			TPM_VOLATILE_CONFIG_DATA,
			L"EventCount",
			RRF_RT_REG_QWORD,
			NULL,
			(PBYTE)pCurrentTpmEventCount,
			&cbData))))
		{
			goto Cleanup;
		}
	}

	if (pCurrentTpmCounterId != NULL)
	{
		// Obtain the current CounterId
		cbData = sizeof(UINT64);
		if (FAILED(hr = HRESULT_FROM_WIN32(RegGetValueW(
			HKEY_LOCAL_MACHINE,
			TPM_VOLATILE_CONFIG_DATA,
			L"CounterId",
			RRF_RT_REG_QWORD,
			NULL,
			(PBYTE)pCurrentTpmCounterId,
			&cbData))))
		{
			goto Cleanup;
		}
	}

	if (pInitialTpmBootCount != NULL)
	{
		// Obtain the current BootCount
		cbData = sizeof(UINT64);
		if (FAILED(hr = HRESULT_FROM_WIN32(RegGetValueW(
			HKEY_LOCAL_MACHINE,
			TPM_VOLATILE_CONFIG_DATA,
			L"InitialBootCount",
			RRF_RT_REG_QWORD,
			NULL,
			(PBYTE)pInitialTpmBootCount,
			&cbData))))
		{
			goto Cleanup;
		}
	}

	if (pInitialTpmEventCount != NULL)
	{
		// Obtain the current EventCount
		cbData = sizeof(UINT64);
		if (FAILED(hr = HRESULT_FROM_WIN32(RegGetValueW(
			HKEY_LOCAL_MACHINE,
			TPM_VOLATILE_CONFIG_DATA,
			L"InitialEventCount",
			RRF_RT_REG_QWORD,
			NULL,
			(PBYTE)pInitialTpmEventCount,
			&cbData))))
		{
			goto Cleanup;
		}
	}

	if (pInitialTpmCounterId != NULL)
	{
		// Obtain the current CounterId
		cbData = sizeof(UINT64);
		if (FAILED(hr = HRESULT_FROM_WIN32(RegGetValueW(
			HKEY_LOCAL_MACHINE,
			TPM_VOLATILE_CONFIG_DATA,
			L"InitialCounterId",
			RRF_RT_REG_QWORD,
			NULL,
			(PBYTE)pInitialTpmCounterId,
			&cbData))))
		{
			goto Cleanup;
		}
	}

Cleanup:
	return hr;
}

HRESULT
PcpToolGetPlatformCounters()
{
	HRESULT hr = S_OK;
	UINT32 OsBootCount = 0;
	UINT32 OsResumeCount = 0;
	UINT64 CurrentTPMBootCount = 0L;
	UINT64 CurrentTPMEventCount = 0L;
	UINT64 CurrentTPMCounterId = 0L;
	UINT64 InitialTPMBootCount = 0L;
	UINT64 InitialTPMEventCount = 0L;
	UINT64 InitialTPMCounterId = 0L;
	WCHAR message[MAX_LOG_MESSAGE_LENGTH];

	if (FAILED(hr = TpmAttGetPlatformCounters(
		&OsBootCount,
		&OsResumeCount,
		&CurrentTPMBootCount,
		&CurrentTPMEventCount,
		&CurrentTPMCounterId,
		&InitialTPMBootCount,
		&InitialTPMEventCount,
		&InitialTPMCounterId
		)))
	{
		goto Cleanup;
	}

	// Output results
	logResult(L"<PlatformCounters>\n");
	PcpToolLevelPrefix(1);
	if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"<OsBootCount>%u</OsBootCount>\n", OsBootCount) >= 0) {
		logResult(message);
	}
	PcpToolLevelPrefix(1);
	if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"<OsResumeCount>%u</OsResumeCount>\n", OsResumeCount) >= 0) {
		logResult(message);
	}
	PcpToolLevelPrefix(1);
	if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"<CurrentBootCount>%I64d</CurrentBootCount>\n", CurrentTPMBootCount) >= 0) {
		logResult(message);
	}
	PcpToolLevelPrefix(1);
	if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"<CurrentEventCount>%I64d</CurrentEventCount>\n", CurrentTPMEventCount) >= 0) {
		logResult(message);
	}
	PcpToolLevelPrefix(1);
	if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"<CurrentCounterId>%I64d</CurrentCounterId>\n", CurrentTPMCounterId) >= 0) {
		logResult(message);
	}
	PcpToolLevelPrefix(1);
	if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"<InitialBootCount>%I64d</InitialBootCount>\n", InitialTPMBootCount) >= 0) {
		logResult(message);
	}
	PcpToolLevelPrefix(1);
	if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"<InitialEventCount>%I64d</InitialEventCount>\n", InitialTPMEventCount) >= 0) {
		logResult(message);
	}
	PcpToolLevelPrefix(1);
	if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"<InitialCounterId>%I64d</InitialCounterId>\n", InitialTPMCounterId) >= 0) {
		logResult(message);
	}
	logResult(L"</PlatformCounters>\n");

Cleanup:
	PcpToolCallResult(L"PcpToolGetPlatformCounters", hr);
	return hr;
}


HRESULT
PcpToolDisplayKey(
	_In_ PCWSTR lpKeyName,
	_In_reads_(cbKey) PBYTE pbKey,
	DWORD cbKey,
	UINT32 level
	)
{
	HRESULT hr = S_OK;
	BCRYPT_RSAKEY_BLOB* pKey = (BCRYPT_RSAKEY_BLOB*)pbKey;
	BYTE pubKeyDigest[20] = { 0 };
	UINT32 cbRequired = 0;
	WCHAR message[MAX_LOG_MESSAGE_LENGTH];

	// Parameter check
	if ((pbKey == NULL) ||
		(cbKey < sizeof(BCRYPT_RSAKEY_BLOB)) ||
		(cbKey < (sizeof(BCRYPT_RSAKEY_BLOB) +
			pKey->cbPublicExp +
			pKey->cbModulus +
			pKey->cbPrime1 +
			pKey->cbPrime2)))
	{
		hr = E_INVALIDARG;
		goto Cleanup;
	}

	PcpToolLevelPrefix(level);
	if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"<RSAKey size=\"%u\"", cbKey) >= 0) {
		logResult(message);
	}
	if ((lpKeyName != NULL) &&
		(wcslen(lpKeyName) != 0))
	{
		if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L" keyName=\"%s\"", lpKeyName) >= 0) {
			logResult(message);
		}
	}
	logResult(L">\n");

	PcpToolLevelPrefix(level + 1);
	if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"<Magic>%c%c%c%c<!-- 0x%08x --></Magic>\n",
		((PBYTE)&pKey->Magic)[0], ((PBYTE)&pKey->Magic)[1], ((PBYTE)&pKey->Magic)[2], ((PBYTE)&pKey->Magic)[3], pKey->Magic) >= 0) {
		logResult(message);
	}


	PcpToolLevelPrefix(level + 1);
	if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"<BitLength>%u</BitLength>\n", pKey->BitLength) >= 0) {
		logResult(message);
	}
	PcpToolLevelPrefix(level + 1);
	if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"<PublicExp size=\"%u\">\n", pKey->cbPublicExp) >= 0) {
		logResult(message);
	}
	PcpToolLevelPrefix(level + 2);
	for (UINT32 n = 0; n < pKey->cbPublicExp; n++)
	{
		if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"%02x", pbKey[sizeof(BCRYPT_RSAKEY_BLOB) + n]) >= 0) {
			logResult(message);
		}
	}
	logResult(L"\n");
	PcpToolLevelPrefix(level + 1);
	logResult(L"</PublicExp>\n");

	PcpToolLevelPrefix(level + 1);
	if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"<Modulus size=\"%u\" digest=\"", pKey->cbModulus) >= 0) {
		logResult(message);
	}
	for (UINT32 n = 0; n < sizeof(pubKeyDigest); n++)
	{
		if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"%02x", pubKeyDigest[n]) >= 0) {
			logResult(message);
		}
	}
	logResult(L"\">\n");
	PcpToolLevelPrefix(level + 2);
	for (UINT32 n = 0; n < pKey->cbModulus; n++)
	{
		if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"%02x", pbKey[sizeof(BCRYPT_RSAKEY_BLOB) + pKey->cbPublicExp + n]) >= 0) {
			logResult(message);
		}
	}
	logResult(L"\n");
	PcpToolLevelPrefix(level + 1);
	logResult(L"</Modulus>\n");

	PcpToolLevelPrefix(level);
	logResult(L"</RSAKey>\n");

Cleanup:
	return hr;
}

HRESULT
PcpToolGetEK_RSK()
	/*++
	Retrieve the EKPub from the TPM through the PCP. The key is provided as a
	BCRYPT_RSAKEY_BLOB structure. Requires Admin rights.
	--*/
{
	HRESULT hr = S_OK;
	PCWSTR fileName = NULL;
	NCRYPT_PROV_HANDLE hProv = NULL;
	BYTE pbEkPub[1024] = { 0 };
	DWORD cbEkPub = 0;
	BYTE pbSrkPub[1024] = { 0 };
	DWORD cbSrkPub = 0;

	if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
		&hProv,
		MS_PLATFORM_CRYPTO_PROVIDER,
		0))))
	{
		goto Cleanup;
	}

	if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(hProv,
		NCRYPT_PCP_EKPUB_PROPERTY,
		pbEkPub,
		sizeof(pbEkPub),
		&cbEkPub,
		0))))
	{
		goto Cleanup;
	}

	if (FAILED(hr = PcpToolDisplayKey(L"EndorsementKey", pbEkPub, cbEkPub, 0)))
	{
		goto Cleanup;
	}

	if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
		hProv,
		NCRYPT_PCP_SRKPUB_PROPERTY,
		pbSrkPub,
		sizeof(pbSrkPub),
		&cbSrkPub,
		0))))
	{
		goto Cleanup;
	}

	// Output result
	if (FAILED(hr = PcpToolDisplayKey(L"StorageRootKey", pbSrkPub, cbSrkPub, 0)))
	{
		goto Cleanup;
	}


Cleanup:
	if (hProv != NULL)
	{
		NCryptFreeObject(hProv);
		hProv = NULL;
	}
	PcpToolCallResult(L"PcpToolGetEK_SRK", hr);
	return hr;
}

HRESULT
PcpToolGetSystemInfo() {
	HRESULT hr = S_OK;
	CHAR message[MAX_LOG_MESSAGE_LENGTH];

	// Device unique ID (generated randomly, stored in file and reused)
	logResult(L"<DeviceUniqueID>");
	const size_t deviceIDLen = 16;
	char	deviceID[deviceIDLen + 1] = {0};
	FILE* idFile = NULL;
	_wfopen_s(&idFile, deviceIDFileName, L"r");
	if (idFile) {
		// File with unique id already exists, use the value
		size_t deviceIDRealLen = fread_s(deviceID, deviceIDLen, 1, deviceIDLen, idFile);
		if (sprintf_s(message, MAX_LOG_MESSAGE_LENGTH, "%s", deviceID) >= 0) {
			logResult(message);
		}
		fclose(idFile);
	}
	else {
		// File with unique id not exists yet, create and generate new unique id
		srand((unsigned int) time(NULL));
		for (size_t i = 0; i < deviceIDLen; i++) {
			deviceID[i] = '0' + rand() % 10;
		}
		_wfopen_s(&idFile, deviceIDFileName, L"w");
		if (idFile != NULL) {
			fwrite(deviceID, deviceIDLen, sizeof(BYTE), idFile);
			fclose(idFile);
		}
		// Use newly generated ID
		if (sprintf_s(message, MAX_LOG_MESSAGE_LENGTH, "%s", deviceID) >= 0) {
			logResult(message);
		}
	}
	logResult(L"</DeviceUniqueID>\n");

	const size_t systemInfoCmdLen = 1000;
	WCHAR systemInfoCmd[systemInfoCmdLen];
	swprintf_s(systemInfoCmd, systemInfoCmdLen, L"systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"OS Manufacturer\" /C:\"OS Configuration\" /C:\"OS Build Type\" /C:\"Original Install Date\" /C:\"System Boot Time\" /C:\"System Manufacturer\" /C:\"System Model\" /C:\"System Type\" /C:\"Processor(s)\" /C:\"BIOS Version\" >> %s", fileName);
	logResult(L"<SystemInfo>\n");
	if (pFile) {
		fclose(pFile); // close file temporarily to allow for system command write
		_wsystem(systemInfoCmd);
		_wfopen_s(&pFile, fileName, L"a");
	}
	logResult(L"</SystemInfo>\n");

	SYSTEM_INFO sysInfo;
	GetNativeSystemInfo(&sysInfo);

	return hr;
}

void PrepareMeasurementFiles(_In_ int argc, _In_reads_(argc) WCHAR* argv[]) {
	WCHAR message[MAX_LOG_MESSAGE_LENGTH];
	SYSTEMTIME st;
	FILETIME ft;
	GetSystemTime(&st);
	SystemTimeToFileTime(&st, &ft);
	// File name format: PCRs_2018-03-30_1957.txt (YYY-MM-DD_HHMM)
	if (argc > 2) {
		swprintf_s(fileName, MAX_FILE_NAME, L"%s\\PCR_%04d-%02d-%02d_%02d%02d.txt", argv[2], st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
		swprintf_s(deviceIDFileName, MAX_FILE_NAME, L"%s\\unique_device_id.txt", argv[2]);
	}
	else {
		swprintf_s(fileName, MAX_FILE_NAME, L"PCR_%04d-%02d-%02d_%02d%02d.txt", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
		swprintf_s(deviceIDFileName, MAX_FILE_NAME, L"unique_device_id.txt");
	}
	_wfopen_s(&pFile, fileName, L"w");

	logResult(L"<Measurement>\n");

	if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"<Version>%s</Version>\n", TPM_PCR_VERSION) >= 0) {
		logResult(message);
	}

	// Time
	if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"<Time>%04d-%02d-%02d_%02d%02d</Time>\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute) >= 0) {
		logResult(message);
	}
	if (swprintf_s(message, MAX_LOG_MESSAGE_LENGTH, L"<TimeUnix>%04d_%04d</TimeUnix>\n", ft.dwHighDateTime, ft.dwLowDateTime) >= 0) {
		logResult(message);
	}
}

void printHelp() {
	wprintf(L"TPM_PCR - a tool for collection of Trusted Platform Module data for research purposes.\n");
	wprintf(L"2018, CRoCS MUNI.\n");
	wprintf(L"Usage: TPM_PCR.exe collect ... collects basic TPM data, store in current folder\n");
	wprintf(L"Usage: TPM_PCR.exe collect <base_path> ... collects basic TPM data, set base directory path as base_path\n");
	wprintf(L"Usage: TPM_PCR.exe collectall ... collects extended TPM data\n");
	wprintf(L"Usage: TPM_PCR.exe schedule ... schedules data collection to run every day at 7pm using Windows Task Scheduler\n");
	wprintf(L"Usage: TPM_PCR.exe ? ... prints this help\n\n");
	wprintf(L"The tool collects device info, TPM version, the current values of TPM PCR registers, TPM platform counters \n");
	wprintf(L"and optionally EK and RSK public key.The measurement is stored into file PCR_date_time.txt(e.g., 'PCR_2018-03-31_1915.txt').\n");
}

void collectData(_In_ int argc, _In_reads_(argc) WCHAR* argv[], bool bCollectAll) {
	PrepareMeasurementFiles(argc, argv);

	// System info via systeminfo tool
	PcpToolGetSystemInfo();

	// TPM info
	PcpToolGetVersion();
	PcpToolGetPCRs();
	PcpToolGetPlatformCounters();

	if (bCollectAll) {
		PcpToolGetEK_RSK(); // Requires admin rights to succeed
	}

	logResult(L"</Measurement>\n");

	fclose(pFile);
}

HRESULT
schedule() {
	HRESULT hr = S_OK;

	wprintf(L"Scheduling repeated executing every day at 7pm (name of task is tpm_pcr_collect)... ");

	WCHAR systemInfoCmd[] = L"schtasks.exe /Create /SC DAILY /ST 19:00 /TN tpm_pcr_collect /TR \"%cd%\\TPM_PCR.exe collect %cd%\"";
	hr = _wsystem(systemInfoCmd);
	if (FAILED(hr)) {
		wprintf(L"failed\n");
	}
	return hr;
}

int __cdecl wmain(_In_ int argc,
	_In_reads_(argc) WCHAR* argv[])
{
	if ((argc <= 1) ||
		(!wcscmp(argv[1], L"/?")) ||
		(!wcscmp(argv[1], L"-?")) ||
		(!_wcsicmp(argv[1], L"/h")) ||
		(!_wcsicmp(argv[1], L"-h")))
	{
		printHelp();
	}
	else
	{
		WCHAR* command = argv[1];
		if (!_wcsicmp(command, L"collect"))
		{
			collectData(argc, argv, false);
		}
		else if (!_wcsicmp(command, L"collectall"))
		{
			collectData(argc, argv, true);
		}
		else if (!_wcsicmp(command, L"schedule"))
		{
			schedule();
		} 
		else
		{
			wprintf(L"Command not found.");
		}
	}
}

