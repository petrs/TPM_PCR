# ideas: Detect and highlight values which are: 1) unique, 2) often used, 3) clearly unused 0000...,/ffff... 4) same value among multiple PCRs
import operator
import random
import os, ntpath
import sys
import xml.etree.ElementTree as ET
import zipfile
from graphviz import Digraph

pcrs = ['00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12', '13', '14', '15', '16', '17',
        '18', '19', '20', '21', '22', '23']


def search_files(folder):
    for root, dirs, files in os.walk(folder):
        yield from [os.path.join(root, x) for x in files]


def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)


def get_pcr_use(pcr_index):
    return {
        0: "PlatformManufacturer; Core root-of-trust for measurement, EFI boot and run-time services, EFI drivers embedded in system ROM, ACPI static tables, embedded SMM code, and BIOS code, INT 19h handler",
        1: "PlatformManufacturer; Platform and motherboard configuration and data. Hand-off tables and EFI variables that affect system configuration, EFI Boot variables and BootOrder variable, and e.x. SAL system table, SMBIOS Tables",
        2: "PlatformManufacturer; Option ROM code, EFI Boot Services Drivers, EFI Runtime Drivers",
        3: "PlatformManufacturer; Option ROM data and configuration, EFI Variable",
        4: "PlatformManufacturer; IPL (Initial Program Loader) Code: usually Master Boot Record (MBR) code or code from other boot devices, Pre-OS diagnostics, EFI OS Loader",
        5: "PlatformManufacturer; Master Boot Record (MBR) partition table, Various EFI variables and the GPT table, NTFS partition table; IPL Code Configuration and Data",
        6: "PlatformManufacturer; Host Platform manufacturer-specific, State transition and wake events",
        7: "PlatformManufacturer; Computer manufacturer-specific, UEFI Secure Boot policy",
        8: "OS; NTFS boot sector",
        9: "OS; NTFS boot block",
        10: "OS; Boot manager",
        11: "OS; BitLocker access control",
        12: "OS; Reserved for future use; WinResume (changes every boot on win10, probably PlatformCounters included - at least OSBootCount)",
        13: "OS; Reserved for future use; WinResume",
        14: "OS; Reserved for future use; WinResume",
        15: "OS; Reserved for future use; Win: Normal drivers (mouse, network);\nAntiMalware runtime could extend additional measurements into the TPM PCR 15 using the Microsoft TPM Driver",
        16: "Debug; resettable without a power cycle",
        17: "TXT; DRTM and launch control policy",
        18: "TXT; Trusted OS start-up code (MLE)",
        19: "TXT; Trusted OS (for example OS configuration)",
        20: "TXT; Trusted OS (for example OS Kernel and other code)",
        21: "Reserved for future use",
        22: "Reserved for future use",
        23: "Reserved for future use"
    }[pcr_index]


def get_pcr_value_info(pcr_hash):
    return {
        'ebb98df76613280f20dc38221143a9e727399486': 'PCR11, Bitlocker enabled',
        '0fe6e8f2110d5d53935c9e7d6f6bf722598b550595aabdc6e4fd2ecdf310f980': 'PCR11, analogy for ebb98df766... for SHA256',
        '3b4ea68141c46cfd3f504d1e77e1a5751e002359': 'PCR07 for some Dell machines',
        '1a2cd95872fb89b99bff60a7d472a89548e0f84a': 'PCR04 for some Dell machines',
        'fc76feaf714c844cc888ea454ddf97c0ed220b61': 'PCR14 ???',
        'b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236': 'PCR02,03,06,01 - possibly hash of some fixed value',
        '3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969': 'PCR02,03,06,01 - possibly hash of some fixed value, analogy of b2a83b0ebf2f83... for SHA256',
        'acced3f7585f064df0cde43a2dac4c9d98d94ef4fcd7433a6082befccc949f1c': 'PCR04, various machines, ???',
        '944c3a62a013e93d2cd21a14ec3f8ca76cb85f395524ac6b259d4de66418b081': 'PCR14 ???',
        'ecfd90aa1e43e8425ad65ddc715f2e412aca1539': 'value of PCR01,02,03,06,07, single machine, possibly unset',
        'ffffffffffffffffffffffffffffffffffffffff': 'unused',
        '0000000000000000000000000000000000000000': 'unused',
        '0000000000000000000000000000000000000000000000000000000000000000': 'unused',
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff': 'unused'
    }.get(pcr_hash, '')


'''
Returns randomly selected color out of defined
@returns color string
'''

colors = ['green', 'red', 'blue', 'magenta', 'brown', 'darkgreen', 'black', 'gray', 'gold', 'chocolate',
          'darkorange1', 'deeppink1', 'cadetblue']
def get_random_color():
    return colors[random.randint(0, len(colors) - 1)]

def get_color(color_index):
    return colors[color_index % len(colors)]


def get_color_by_device_name(device_name):
    if device_name.find('DRYADA') != -1: return 'red'
    if device_name.find('FAIAX') != -1: return 'green'
    if device_name.find('NAIADA') != -1: return 'blue'
    if device_name.find('NEREIS') != -1: return 'black'
    if device_name.find('SIRENE') != -1: return 'gold'
    if device_name.find('TITAN') != -1: return 'darkorange1'

    return get_random_color()


'''
Returns randomly selected edge style
@returns edge style string
'''


def get_random_edge_style():
    edge_styles = ['solid', 'dashed', 'bold']
    return edge_styles[random.randint(0, len(edge_styles) - 1)]


def extract_all_zips(walk_dir):
    '''
    Extracts all zip files for separate devices. Previously extracted files are overwritten
    '''
    zip_files = []
    for filename in search_files(walk_dir):
        if os.path.isfile(filename):
            filenameonly, file_extension = os.path.splitext(filename)
            # proceed only from file with txt appendix
            if file_extension == '.zip':
                zip_files.append(filename)

    for filename in zip_files:
        dir_path = filename[0:filename.rfind('\\') + 1]
        zip_ref = zipfile.ZipFile(filename, 'r')
        zip_ref.extractall(dir_path)
        zip_ref.close()


'''
Recursively reads files with TPM PCR info from the provided directory. 
@param walk_dir: directory with stored results for cards
@param pcr_values: output dictionary  
'''

def process_tpm_files(walk_dir, pcr_values):
    # expected structure
    # DRYADA01 // folder, device_name
    # ---> PCR_2018-10-22_1700.txt // file with measurement
    # ---> PCR_2018-11-23_1700.txt // another file with measurement
    # DRYADA02 // another device

    for filename in search_files(walk_dir):
        #print(filename)
        if os.path.isfile(filename):
            filenameonly, file_extension = os.path.splitext(filename)
            # proceed only from file with txt appendix
            if file_extension != '.txt':
                print('skipping file ' + filename)
                continue

            # directory is device name, e.g., DRYADA01
            subdirs = filename.split('\\')
            devicename = subdirs[len(subdirs) - 2]
            filenameonly = subdirs[len(subdirs) - 1]

            # check if device is already inserted
            if not devicename in pcr_values:
                pcr_values[devicename] = {}

            pcr_values[devicename][filenameonly] = {}

            try:
                root = ET.parse(filename).getroot()
                time_tag = root.find('Time')
                filetime = time_tag.text

                for type_tag in root.findall('PCRs/PCR'):
                    pcrindex = type_tag.get('Index')
                    pcrhash = type_tag.text
                    #print(pcrindex)
                    #print(pcrhash)

                    pcr_values[devicename][filenameonly][pcrindex] = pcrhash
                    pcr_values[devicename][filenameonly]['time'] = filetime
            except:
                e = sys.exc_info()[0]
                print(e)


""" 
Visualize CPLC information from the list of cards 
@param cplc_list: list of hash maps (with CPLC metadata) for the cards to process and visualize  
@param vendor_name_filter: if empty string '', then all vendors are printed, otherwise only the provided vendor is generated 
"""


def generate_graph(path, pcr_index, pcr_values, shall_view, random_color):
    # Graph with only first and last measured PCR hash
    dot = Digraph(comment='PCR values (TPM_PCR project)')
    dot.attr('graph', label='Directory: {} \n PCR values (TPM_PCR project)\n PCR{}: {} \nPCR_INDEX -> FIRST_PCR_VALUE -> LAST_PCR_VALUE'.format(path, pcr_index, get_pcr_use(int(pcr_index))), labelloc='t', fontsize='30')
    dot.attr(rankdir='LR', size='8,5')

    # Graph with all PCR hash values
    dot2 = Digraph(comment='PCR values (TPM_PCR project)')
    dot2.attr('graph',
              label='Directory: {} \n PCR values (TPM_PCR project)\n PCR{}: {} \n PCR_INDEX -> PCR_VALUE -> next_PCR_VALUE -> ... next_PCR_VALUE'.format(path, pcr_index, get_pcr_use(int(pcr_index))), labelloc='t', fontsize='30')
    dot2.attr(rankdir='LR', size='8,5')

    pcr_node_label = 'PCR={}'.format(pcr_index)

    dot.node(pcr_node_label)
    dot2.node(pcr_node_label)

    for device_name in pcr_values.keys():
        if random_color:
            rndcolor = get_random_color()
            rndedgestyle = get_random_edge_style()
        else:
            rndcolor = get_color_by_device_name(device_name)
            rndedgestyle = 'bold'

        device_values = pcr_values[device_name]

        prev_pcr_hash = pcr_node_label
        pcr_trans_label = ''
        last_time = ''

        first_pcr_hash = ''
        first_time = ''

        for measurement_name in device_values.keys():
            if not pcr_index in device_values[measurement_name]:
                print('WARNING: PCR {} not found for device {}, measurement {}'.format(pcr_index, device_name, measurement_name))
                continue

            pcr_hash = device_values[measurement_name][pcr_index]
            if first_pcr_hash == '':
                first_pcr_hash = pcr_hash

            # update label with measurement name
            #pcr_trans_label = pcr_trans_label + ',{}'.format(device_values[measurement_name]['time'])
            #pcr_trans_label_count = pcr_trans_label_count + 1
            #if pcr_trans_label_count > 5:
            #    pcr_trans_label = pcr_trans_label + '\n'
            #    pcr_trans_label_count = 0

            if first_time == '':
                first_time = device_values[measurement_name]['time']

            last_time = device_values[measurement_name]['time']
            if pcr_trans_label == '':
                pcr_trans_label = '{}, {}'.format(device_name, last_time)


            # check if pcr value changed - of not, just update label, if yes, create new node
            if pcr_hash != prev_pcr_hash:
                # pcr change
                dot2.node(pcr_hash)
                pcr_trans_label = pcr_trans_label + ' to {}'.format(last_time)
                dot2.edge(prev_pcr_hash, pcr_hash, color=rndcolor, style=rndedgestyle, label=pcr_trans_label)
                pcr_trans_label = ''

            prev_pcr_hash = pcr_hash

        # writeout remaining data
        dot.node(first_pcr_hash)
        dot.node(pcr_hash)
        pcr_trans_label = '{} {} BEGIN'.format(device_name, first_time)
        dot.edge(pcr_node_label, first_pcr_hash, color=rndcolor, style=rndedgestyle, label=pcr_trans_label)
        pcr_trans_label = '{} {} END'.format(device_name, last_time)
        dot.edge(first_pcr_hash, pcr_hash, color=rndcolor, style=rndedgestyle, label=pcr_trans_label)

        dot2.node(pcr_hash)
        pcr_trans_label = pcr_trans_label + ' to {} END'.format(last_time)
        dot2.edge(prev_pcr_hash, pcr_hash, color=rndcolor, style=rndedgestyle, label=pcr_trans_label)

    # Generate dot graph using GraphViz into pdf
    dot.render('pcr-output/pcr_first_last_{}'.format(pcr_index), view=shall_view)
    #dot2.render('pcr-output/pcr_{}'.format(pcr_index), view=shall_view)


def compute_pcr_stats(pcr_values):
    pcr_hash_stats_simple = {}
    pcr_hash_stats_numdevices_simple = {}
    pcr_hash_stats = {}
    for device_name in pcr_values.keys():

        device_values = pcr_values[device_name]

        for measurement_name in device_values.keys():
            for pcr_index in pcrs:
                if not pcr_index in device_values[measurement_name]:
                    continue

                pcr_hash = device_values[measurement_name][pcr_index]

                if not pcr_hash in pcr_hash_stats:  # new hash
                    pcr_hash_stats_simple[pcr_hash] = 0
                    pcr_hash_stats_numdevices_simple[pcr_hash] = 0
                    pcr_hash_stats[pcr_hash] = {}
                    pcr_hash_stats[pcr_hash]['devices'] = []

                if not pcr_index in pcr_hash_stats[pcr_hash]:  # new hash
                    pcr_hash_stats[pcr_hash][pcr_index] = 0

                if not device_name in pcr_hash_stats[pcr_hash]['devices']:  # new device with this hash
                    pcr_hash_stats[pcr_hash]['devices'].append(device_name)
                    pcr_hash_stats_numdevices_simple[pcr_hash] = 0

                pcr_hash_stats_simple[pcr_hash] = pcr_hash_stats_simple[pcr_hash] + 1
                pcr_hash_stats[pcr_hash][pcr_index] = pcr_hash_stats[pcr_hash][pcr_index] + 1
                pcr_hash_stats_numdevices_simple[pcr_hash] = len(pcr_hash_stats[pcr_hash]['devices'])

    sorted_pcr_hash_stats_simple = sorted(pcr_hash_stats_simple.items(), key=operator.itemgetter(1), reverse=True)

    sorted_pcr_hash_num_devices_stats = sorted(pcr_hash_stats_numdevices_simple.items(), key=operator.itemgetter(1), reverse=True)

    return pcr_hash_stats, sorted_pcr_hash_stats_simple, sorted_pcr_hash_num_devices_stats


def print_pcr(pcr_hash_stats, pcr_stats, verbose):
    for pcr_hash in pcr_hash_stats:
        label = ''
        for pcr_index in pcr_stats[pcr_hash[0]]:
            if pcr_index == 'devices':
                continue

            pcr_stats_item = pcr_stats[pcr_hash[0]][pcr_index]
            label = label + 'PCR{}:{}x, '.format(pcr_index, pcr_stats_item)

        if verbose:
            print('{}x: {}({})\n\t:: {}\n\t::: #devices={}: {}\n'.format(pcr_hash[1], pcr_hash[0], get_pcr_value_info(pcr_hash[0]), label, len(pcr_stats[pcr_hash[0]]['devices']), pcr_stats[pcr_hash[0]]['devices']))
        else:
            print('{}x: {}({}) {} #devices={}\n'.format(pcr_hash[1], pcr_hash[0], get_pcr_value_info(pcr_hash[0]), label, len(pcr_stats[pcr_hash[0]]['devices'])))


def print_pcr_stats(pcr_stats, sorted_pcr_stats, sorted_pcr_hash_num_devices_stats):
    print('### SORTED BY NUMBER OF OCCURENCE OF PARTICULAR PCR HASH, VERBOSE #######################\n\n\n')
    print_pcr(sorted_pcr_stats, pcr_stats, True)
    print('### SORTED BY NUMBER OF OCCURENCE OF PARTICULAR PCR HASH #######################\n\n\n')
    print_pcr(sorted_pcr_stats, pcr_stats, False)
    print('### SORTED BY NUMBER OF DEViCES WITH PARTICULAR PCR HASH #######################\n\n\n')
    print_pcr(sorted_pcr_hash_num_devices_stats, pcr_stats, False)

def render_all_pcrs():
    # Read all files, extract device name, plot all PCRs for given index, connector labeled with device name
    # different connector color for different machine
    # Questions to answer: Are same devices coming with the same PCR hash? Are different

    pcr_values = {}

    #walk_dir = 'c:\\!!!TPM\\TPM_PCR_FI\\PCR_measurements_test\\'
    #walk_dir = 'c:\\!!!TPM\\!python_test\\'
    #walk_dir = 'c:\\!!!TPM\\TPM_PCR_FI\\PCR_measurements_test_22.10.2018-16.06.2019\\'
    walk_dir = 'c:\\!!!TPM\\TPM_PCR_FI\\PCR_measurements_22.10.2018-04.08.2020\\'

    extract_all_zips(walk_dir)
    process_tpm_files(walk_dir, pcr_values)

    print(pcr_values)

    # compute PCR values statistics
    pcr_stats, sorted_pcr_stats, sorted_pcr_hash_num_devices_stats = compute_pcr_stats(pcr_values)
    # print PCR stats
    print_pcr_stats(pcr_stats, sorted_pcr_stats, sorted_pcr_hash_num_devices_stats)

    # generate graphviz visualization for different PCRs
    for pcr in pcrs:
        generate_graph(walk_dir, pcr, pcr_values, False, False)
        print('PCRs for index {} generated'.format(pcr))


def main():
    # Pick suitable seed so that different lines in graph are rendered with different colors/types (needs manual testing)
    random.seed(10)

    render_all_pcrs()


if __name__ == "__main__":
    main()
