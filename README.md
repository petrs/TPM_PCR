# TPM_PCR
A tool for collection of Trusted Platform Module register values for the research purposes

## Single run

1. Download the most recent build of TPM_PCR tool
2. Run following command to collect basic info.
```
TPM_PCR.exe collect
```
3. Investigate the resulting file (PCR_date_time.txt)

## Repeated run using Windows task scheduler
Schedule the data collection every day using Windows task scheduler (run every day at 8pm, task name is tpm_pcr_collect):
```
schtasks.exe /Create /SC DAILY /ST 20:00 /TN tpm_pcr_collect /TR "%cd%\TPM_PCR.exe collect %cd%"
```
Every device is assigned with unique number stored in file ''unique_device_id.txt''. If not found, new unique ID is generated and stored into file.

## Usage
```
  TPM_PCR.exe collect ... collects basic TPM data, store in current folder
  
  TPM_PCR.exe collect <base_path> ... collects basic TPM data, set base directory path as base_path
  
  TPM_PCR.exe collectAll ... collects extended TPM data
  
  TPM_PCR.exe ? ... prints help
  
  The tool collects device info, TPM version, the current values of TPM PCR registers, TPM platform counters and optionally EK and RSK public key.The measurement is stored into file PCR_date_time.txt (e.g., 'PCR_2018-03-31_1915.txt').
```  
  
