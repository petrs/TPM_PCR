# TPM_PCR - a tool for TPM PCRs collection

A tool for the unattended collection of [Trusted Platform Module](https://en.wikipedia.org/wiki/Trusted_Platform_Module) platform counter registers (PCRs). The basic functionality is taken from [Microsoft PCPTool TSS.MSR](https://github.com/Microsoft/TSS.MSR/tree/master/PCPTool.v11) and is modified to automatically and repeatedly collect PCR measurements into separate files. A basic system info and random id to logically connect measurements from the same device are also inserted. The application may require the installation of [Microsoft Visual C++ 2015 Redistributable Package](https://www.microsoft.com/en-us/download/details.aspx?id=53840).

## Single run

1. Download the most recent build of TPM_PCR tool
2. Run the following command to collect basic info.
```
TPM_PCR.exe collect
```
3. Investigate the resulting file (PCR_xxx_xxx.txt)

## Repeated run using Windows task scheduler
The PCRs are occasionally changing based on software updates and other platform changes. The data collection can be scheduled to run automatically every day using Windows task scheduler using the following command executed from (example: run every day at 8 pm, task name is tpm_pcr_collect):
```
schtasks.exe /Create /SC DAILY /ST 20:00 /TN tpm_pcr_collect /TR "%cd%\TPM_PCR.exe collect %cd%"
```
Every device is assigned with unique number stored in file ''unique_device_id.txt''. If not found, new unique ID is generated and stored into a file.

## Example result
```xml
<Measurement>
<Time>2018-03-31_1915</Time>
<TimeUnix>30656804_-1705709280</TimeUnix>
<DeviceUniqueID>3260123883014769</DeviceUniqueID>
<SystemInfo>
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.16299 N/A Build 16299
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Original Install Date:     29/12/2017, 22:21:07
System Boot Time:          21/03/2018, 09:13:00
System Manufacturer:       Hewlett-Packard
System Model:              HP EliteBook 840 G2
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
BIOS Version:              Hewlett-Packard M71 
</SystemInfo>
<Version>
  <Provider>v01.00</Provider>
  <TPM>
    TPM-Version:01.02-SpecLevel:2-Errata:3-VendorID:'IFX '-Firmware:04.40
  </TPM>
</Version>
<PCRs>
  <PCR Index="00">8cb1a2e093cf41c1a726bab3e10bc1750180bbc5</PCR>
  <PCR Index="01">b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236</PCR>
  <PCR Index="02">b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236</PCR>
  <PCR Index="03">b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236</PCR>
  <PCR Index="04">4dea26d116f8a7bc1a06f4c121e8088a29a61ec5</PCR>
  <PCR Index="05">7d0c0c5eb175d434704e39a775d9292ffab8ffa9</PCR>
  <PCR Index="06">b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236</PCR>
  <PCR Index="07">b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236</PCR>
  <PCR Index="08">0000000000000000000000000000000000000000</PCR>
  <PCR Index="09">0000000000000000000000000000000000000000</PCR>
  <PCR Index="10">0000000000000000000000000000000000000000</PCR>
  <PCR Index="11">ebb98df76613280f20dc38221143a9e727399486</PCR>
  <PCR Index="12">c5f2119b3d5e5fa2104e88755add3e3270f1c60d</PCR>
  <PCR Index="13">f34749fa6843f9e0b3994b1627894c915332a013</PCR>
  <PCR Index="14">fc76feaf714c844cc888ea454ddf97c0ed220b61</PCR>
  <PCR Index="15">0000000000000000000000000000000000000000</PCR>
  <PCR Index="16">0000000000000000000000000000000000000000</PCR>
  <PCR Index="17">ffffffffffffffffffffffffffffffffffffffff</PCR>
  <PCR Index="18">ffffffffffffffffffffffffffffffffffffffff</PCR>
  <PCR Index="19">ffffffffffffffffffffffffffffffffffffffff</PCR>
  <PCR Index="20">ffffffffffffffffffffffffffffffffffffffff</PCR>
  <PCR Index="21">ffffffffffffffffffffffffffffffffffffffff</PCR>
  <PCR Index="22">ffffffffffffffffffffffffffffffffffffffff</PCR>
  <PCR Index="23">0000000000000000000000000000000000000000</PCR>
</PCRs>
<PlatformCounters>
  <OsBootCount>191</OsBootCount>
  <OsResumeCount>2</OsResumeCount>
  <CurrentBootCount>0</CurrentBootCount>
  <CurrentEventCount>289</CurrentEventCount>
  <CurrentCounterId>123456789</CurrentCounterId>
  <InitialBootCount>0</InitialBootCount>
  <InitialEventCount>287</InitialEventCount>
  <InitialCounterId>123456789</InitialCounterId>
</PlatformCounters>
</Measurement>
```

## Do I even have TPM chip in my computer?
Not all computers are equipped with the TPM chip. An easy option to figure out is to press WinButton+R and then type ''tpm.msc''. The TPM management console will display necessary information.

## Usage
```
  TPM_PCR.exe collect ... collects basic TPM data, store in a current folder
  TPM_PCR.exe collect <base_path> ... collects basic TPM data, set base directory path as base_path
  TPM_PCR.exe collectAll ... collects extended TPM data
  TPM_PCR.exe TPM_PCR.exe schedule ... schedules data collection to run every day at 7 pm using Windows Task Scheduler
  
  TPM_PCR.exe ? ... prints help
  
The tool collects device info, TPM version, the current values of TPM PCR registers, TPM platform counters and optionally EK and RSK public key.The measurement is stored in file PCR_date_time.txt (e.g., 'PCR_2018-03-31_1915.txt').
```  
