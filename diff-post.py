import os, re, time, shutil, argparse
import subprocess, resource
import hashlib
from glob import glob
from multiprocessing import Pool
from datetime import datetime

randomness_patterns = [
    '\d+[:|/]\d+[:|/]\d+', # date like 01:01:2022, 01/01/2022
    '\d+[:|/]\d+[:|/]\d+', # date like 01:01:2022, 01/01/2022
    '{}[\d|-]+'.format(datetime.today().strftime('%Y-%m-%d')), # today 
    '{}[\d|-]+'.format(datetime.today().strftime('%m-%d-%Y')), # today 
    '{}\d+'.format(datetime.today().strftime('%Y%m%d')), # today 
    '{}\d+'.format(datetime.today().strftime('%m%d%Y')), # today 
    '{}\d\d\d\d\d\d'.format(str(time.time())[:4]), # timestamp, replace the first 4 numbers with the current timestamp
]

parser = argparse.ArgumentParser(description='')
parser.add_argument('--bin', dest='binary', required=True, help='Binary path')
parser.add_argument('--args', dest='arguments', required=True, help='Arguments to binary')
parser.add_argument('-c', dest='num_com', type=int, required=True, help='The number of compiler configurations')
parser.add_argument('--out_file', dest='out_file', default='', required=False, help='The output filename if the target is not producing outputs to stdout.')
parser.add_argument('--threads', dest='threads', default=1, type=int, required=False, help='Threads to use (default=1)')
parser.add_argument('-i', dest='in_dir', required=True, help='input dir')
parser.add_argument('-o', dest='out_dir', required=True, help='output dir')
parser.add_argument('-t', dest='tmout', type=int, required=False, help='timeout, default=5 seconds')
parser.add_argument('-m', dest='mem', type=int, default=500, required=False, help='memory limit, default=500 MB')
parser.add_argument('-r', dest='R', type=int, required=False, help='0/1 (default=0), if filter out common randomness. You can customize randomness patterns by editing this file.')
args = parser.parse_args()


def filter_randomness(diff_f, given_tmp_out=None):
    diff_cksum_list = []
    for num_c in range(args.num_com):
        tmp_out = '{}/outputs/out_{}_{}'.format(args.out_dir, diff_f.split('/')[-1], num_c)
        with open(tmp_out, 'rb') as f:
            data = f.read()
        for pattern in randomness_patterns:
            matched = re.findall(bytes(pattern, encoding='utf-8'), data)
            for item in matched:
                data = data.replace(item, b'')
        with open(tmp_out, 'wb') as f:
            f.write(data)
        process = subprocess.run(f'md5sum {tmp_out}', timeout=args.tmout, shell=True, capture_output=True)
        md5sum = process.stdout.decode('utf-8').replace(f' {tmp_out}', '')
        diff_cksum_list.append(md5sum)
    if len(set(diff_cksum_list)) == 1:
        return 1
    return 0


def rerun_target(ori_diff_f):
    diff_f = os.path.join(args.out_dir, ori_diff_f.split('/')[-1].replace(',', '_').replace(':', '_').replace('/', '_').replace('.', '').replace('(', '').replace(')', ''))
    shutil.copy(ori_diff_f, diff_f)
    cksum_list = []
    tmpout_list = []
    subprocess.run('ulimit -Sv {}'.format(args.mem * 1000), shell=True)
    for num_c in range(args.num_com):
        tmp_out = '{}/outputs/out_{}_{}'.format(args.out_dir, diff_f.split('/')[-1], num_c)
        tmp_err = '{}/outputs/err_{}_{}'.format(args.out_dir, diff_f.split('/')[-1], num_c)
        try:
            if args.out_file:
                command = f'{args.binary}-{num_c} {args.arguments} 2>{tmp_err}'.replace('@@', diff_f).replace(args.out_file, tmp_out)
            else:
                command = f'{args.binary}-{num_c} {args.arguments} 1>{tmp_out} 2>{tmp_err}'.replace('@@', diff_f)
            subprocess.run(command, timeout=args.tmout, shell=True, capture_output=False)
            if os.path.exists(tmp_out):
                with open(tmp_out, 'rb') as f:
                    data = f.read()
                with open(tmp_err, 'rb') as f:
                    data += f.read()
            with open(tmp_out, 'wb') as f:
                f.write(data.replace(bytes(f'{args.binary}-{num_c}:', encoding='utf-8'), b'').replace(bytes(tmp_out, encoding='utf-8'), b''))
        except subprocess.TimeoutExpired:
            print('timeouts {}'.format(diff_f.split('/')[-1]))
            shutil.copy(diff_f, '{}/timeouts/{}'.format(args.out_dir, diff_f.split('/')[-1]))
            if os.path.exists(f'{tmp_out}'):
                os.remove(f'{tmp_out}')
            if os.path.exists(f'{tmp_err}'):
                os.remove(f'{tmp_err}')
            return 0
        tmpout_list.append(tmp_out)
        process = subprocess.run(f'md5sum {tmp_out}', timeout=args.tmout, shell=True, capture_output=True)
        md5sum = process.stdout.decode('utf-8').replace(f' {tmp_out}', '')
        cksum_list.append(md5sum)

    if args.R and not filter_randomness(diff_f):
        shutil.copy(diff_f, '{}/diffs/{}'.format(args.out_dir, diff_f.split('/')[-1]))
        os.remove(diff_f)
        return
    if len(set(cksum_list)) != 1:
        shutil.copy(diff_f, '{}/diffs/{}'.format(args.out_dir, diff_f.split('/')[-1]))
        os.remove(diff_f)
        return
    os.remove(diff_f)
    for num_c in range(args.num_com):
        tmp_out = '{}/outputs/out_{}_{}'.format(args.out_dir, diff_f.split('/')[-1], num_c)
        tmp_err = '{}/outputs/err_{}_{}'.format(args.out_dir, diff_f.split('/')[-1], num_c)
        if os.path.exists(f'{tmp_out}'):
            os.remove(f'{tmp_out}')
        if os.path.exists(f'{tmp_err}'):
            os.remove(f'{tmp_err}')
    
if __name__=='__main__':
    args = parser.parse_args()

    if os.path.exists(f'{args.out_dir}'):
        print(f'out_dir: {args.out_dir} exists!')
        exit(1)

    if not os.path.exists(f'{args.out_dir}/timeouts'):
        os.makedirs(f'{args.out_dir}/timeouts')
    if not os.path.exists(f'{args.out_dir}/diffs'):
        os.makedirs(f'{args.out_dir}/diffs')
    if not os.path.exists(f'{args.out_dir}/outputs'):
        os.mkdir(f'{args.out_dir}/outputs')

    diff_files = glob(f'{args.in_dir}/*')
    diff_files.sort()
    print("Total diffs: ", len(diff_files))
    if args.threads > 1:
        with Pool(args.threads) as p:
            p.map(rerun_target, diff_files)
    else:
        for diff_f in diff_files:
            rerun_target(diff_f)
    
    print("\n" + "="*20 + "\n")
    print("Original #diffs: ", len(diff_files))
    print("Now      #diffs: ", len(glob(f'{args.out_dir}/diffs/*')))
    print("Now   #timeouts: ", len(glob(f'{args.out_dir}/timeouts/*')))