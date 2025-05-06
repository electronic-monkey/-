import re
import subprocess
import os
import yaml
import requests
import json
from pathlib import Path
import pandas as pd
from datetime import datetime
import logging

from typing import Set, Dict, List, Optional, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Semaphore

# 性能优化配置
MAX_CONCURRENT = 10  # 最大并发数
REQUEST_INTERVAL = 0.5  # 请求间隔(秒)
semaphore = Semaphore(MAX_CONCURRENT)
last_request_time = 0

# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)


def show_subdomain_menu():
    colors = {
        "option1": "\033[1;32m",  # 绿色加粗
        "option2": "\033[1;33m",  # 黄色加粗
        "option3": "\033[1;34m",  # 蓝色加粗
        "option4": "\033[1;35m",  # 紫色加粗
        "option5": "\033[1;36m",  # 紫色加粗
        "option0": "\033[1;37m",  # 白色加粗
        "reset": "\033[0m"
    }
    print(f"""
{colors['option1']}[+] 1. 使用subfinder收集子域名{colors['reset']}
{colors['option2']}[2] 使用crt.sh收集子域名{colors['reset']}
{colors['option3']}[3] 使用SecurityTrails API收集{colors['reset']}
{colors['option4']}[4] 一键收集（调用所有方法）{colors['reset']}
{colors['option5']}[5] 使用ZoomEye API收集子域名{colors['reset']}
{colors['option0']}[0] 返回主菜单{colors['reset']}

""")


def run(config: Dict) -> None:
    """
    子域名收集主函数
    :param config: 配置字典
    """
    if not isinstance(config, dict):
        logging.error("配置参数类型错误")
        return

    try:
        # 检查模块配置
        if not config.get('subdomain', {}).get('enabled', False):
            logging.warning("子域名收集模块未启用")
            return

        # 创建输出目录
        output_dir = Path('results/subdomains')
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(exist_ok=True)

        # 初始化API配置
        api_keys = {
            'securitytrails': config.get('subdomain', {}).get('securitytrails_api_key'),
            'zoomeye': config.get('subdomain', {}).get('zoomeye_api_key'),
            'shodan': config.get('subdomain', {}).get('shodan_api_key')
        }
    except Exception as e:
        logging.error(f"初始化子域名收集模块时发生错误: {e}")
        return

    while True:
        show_subdomain_menu()
        choice = input("请选择收集方式(0 - 5): ")

        if choice == '0':
            return
        elif choice not in ['1', '2', '3', '4', '5']:
            logging.warning("无效选择，请重新输入")
            continue

        # 验证域名输入
        domain = input("请输入要收集子域名的目标域名(如example.com): ").strip()
        if not domain:
            logging.warning("域名不能为空")
            continue
        if not validate_domain(domain) and not (os.path.exists(domain) and domain.endswith('.txt')):
            logging.error(f"无效的域名格式或文件路径: {domain}")
            continue

        # 准备输出文件
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = str(output_dir / f"subdomains_{domain}_{timestamp}.xlsx")
        results: Dict[str, Set[str]] = {}

        if choice == '1':
            results['subfinder'] = run_subfinder(config, domain, output_file)
            if results['subfinder']:
                logging.info(f"子域名收集结果已保存到 {output_file}")
            break
        elif choice == '2':
            results['crtsh'] = run_crtsh(config, domain, output_file)
            if results['crtsh']:
                logging.info(f"子域名收集结果已保存到 {output_file}")
            break
        elif choice == '3':
            if not api_keys['securitytrails']:
                logging.error("SecurityTrails API密钥未配置")
                continue
            results['securitytrails'] = run_securitytrails(config, domain, output_file)
            if results['securitytrails']:
                logging.info(f"子域名收集结果已保存到 {output_file}")
        elif choice == '4':
            # 一键收集所有可用方法的子域名
            logging.info("开始一键收集子域名...")
            results: Dict[str, Set[str]] = {}

            # 定义收集任务
            collection_tasks = [
                ('subfinder', lambda: run_subfinder(config, domain, output_file)),
                ('crtsh', lambda: run_crtsh(config, domain, output_file)),
                ]

            # 添加需要API密钥的任务
            if api_keys['securitytrails']:
                collection_tasks.append(
                    ('securitytrails', lambda: run_securitytrails(config, domain, output_file))
                )
                logging.info("正在使用SecurityTrails API收集子域名...")
            if api_keys['zoomeye']:
                collection_tasks.append(
                    ('zoomeye', lambda: run_zoomeye(config, domain, output_file))
                )
            if api_keys['shodan']:
                collection_tasks.append(
                    ('shodan', lambda: run_shodan(config, domain, output_file))
                )

            # 并发执行收集任务
            with ThreadPoolExecutor(max_workers=min(4, len(collection_tasks))) as executor:
                future_to_task = {executor.submit(task[1]): task[0] for task in collection_tasks}
                completed = 0
                total_tasks = len(future_to_task)

                for future in as_completed(future_to_task):
                    task_name = future_to_task[future]
                    completed += 1
                    try:
                        result = future.result()
                        results[task_name] = result
                        if result:
                            logging.info(f"[{completed}/{total_tasks}] {task_name} 收集完成，找到 {len(result)} 个子域名")
                        else:
                            logging.warning(f"[{completed}/{total_tasks}] {task_name} 未找到子域名")
                    except Exception as e:
                        logging.error(f"[{completed}/{total_tasks}] {task_name} 收集失败: {e}")
                        results[task_name] = set()

            # 保存结果
            if any(domains for domains in results.values()):
                if save_results_to_excel(results, output_file):
                    combined_result = set().union(*[s for s in results.values() if s])
                    logging.info(f"\n所有子域名收集结果已保存到: {output_file}")
                    logging.info(f"共收集到 {len(combined_result)} 个独特子域名")
                    
                    # 记录每个方法的结果统计
                    for method, domains in results.items():
                        if domains:
                            logging.info(f"{method} 收集到 {len(domains)} 个子域名")
                else:
                    logging.error("保存结果到Excel文件失败")
            else:
                logging.warning("所有收集方法均未找到子域名")
                return



        # 比较新旧子域名
        try:
            compare_subdomains(domain, output_file)
        except Exception as e:
            print(f"子域名收集失败: {e}")


def validate_domain(domain: str) -> bool:
    """
    验证域名格式是否合法
    :param domain: 待验证的域名
    :return: 域名是否合法
    """
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_pattern.match(domain))

def read_file_with_encoding(file_path: str) -> Set[str]:
    """
    使用多种编码尝试读取文件内容
    :param file_path: 文件路径
    :return: 文件内容集合
    """
    encodings = ['utf-8', 'gbk', 'utf-8-sig']
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                return set(line.strip() for line in f if line.strip())
        except UnicodeDecodeError:
            continue
        except Exception as e:
            logging.error(f"读取文件 {file_path} 时发生错误: {e}")
    return set()

def save_results_to_excel(results: Dict[str, Set[str]], output_file: str) -> bool:
    """
    将结果保存到Excel文件
    :param results: 结果字典
    :param output_file: 输出文件路径
    :return: 是否保存成功
    """
    try:
        with pd.ExcelWriter(output_file) as writer:
            for source, domains in results.items():
                if domains:
                    pd.DataFrame(sorted(domains), columns=['子域名']).to_excel(
                        writer, sheet_name=source, index=False
                    )
            if any(domains for domains in results.values()):
                combined_result = set().union(*[s for s in results.values() if s])
                pd.DataFrame(sorted(combined_result), columns=['子域名']).to_excel(
                    writer, sheet_name='合并结果', index=False
                )
        return True
    except Exception as e:
        logging.error(f"保存结果到Excel文件时发生错误: {e}")
        return False

def run_subfinder(config: Dict, domain: str, output_file: str) -> Set[str]:
    """
    使用subfinder.exe进行子域名收集
    :param config: 配置字典
    :param domain: 目标域名
    :param output_file: 输出文件路径
    :return: 收集到的子域名集合
    """
    tools_path = config['global'].get('tools_path', 'tools')
    result_domains = set()
    try:
        subfinder_path = os.path.join(tools_path, 'subfinder.exe')
        if not os.path.exists(subfinder_path):
            logging.error("未找到subfinder.exe，请确保程序已放置在项目根目录")
            return result_domains

        # 处理输入域名
        clean_domain = domain.strip('"')
        is_file_input = os.path.exists(clean_domain) and clean_domain.endswith('.txt')

        # 准备输出文件路径
        if is_file_input:
            filename = os.path.basename(clean_domain)
            safe_filename = re.sub(r'[\\/:*?"<>|]', '_', filename)
            safe_output = os.path.join('results', 'subdomains', 
                                      f"subdomains_{os.path.splitext(safe_filename)[0]}.txt")
            cmd = [str(subfinder_path), "-dL", clean_domain, "-o", str(safe_output), "-all"]
        else:
            if not validate_domain(clean_domain):
                logging.error(f"无效的域名格式: {clean_domain}")
                return result_domains
            safe_domain = re.sub(r'[\\/:*?"<>|]', '_', clean_domain)
            safe_output = os.path.join('results', 'subdomains', f"subdomains_{safe_domain}.txt")
            cmd = [str(subfinder_path), "-d", clean_domain, "-o", safe_output, "-all"]

        logging.info(f"正在使用subfinder收集{domain}的子域名...")
        logging.debug(f"执行命令: {' '.join(cmd)}")

        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        if result.stdout:
            logging.debug(f"subfinder 标准输出: {result.stdout}")
        if result.stderr:
            logging.warning(f"subfinder 标准错误: {result.stderr}")

        if os.path.exists(safe_output):
            result_domains = read_file_with_encoding(safe_output)
            if result_domains:
                logging.info(f"subfinder收集完成，找到{len(result_domains)}个子域名")
            else:
                logging.warning("subfinder未找到任何子域名")
        else:
            logging.error(f"subfinder执行成功，但未找到输出文件: {safe_output}")

    except subprocess.CalledProcessError as e:
        logging.error(f"subfinder执行失败: {e}")
        if e.stderr:
            logging.error(f"错误输出: {e.stderr}")
    except Exception as e:
        logging.error(f"运行subfinder时发生未知错误: {e}")

    return result_domains


# 将API调用逻辑封装到独立函数中

def call_crt_sh_api(domain):
    api_url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(api_url, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"crt.sh API请求失败: {e}")
        return None

def call_securitytrails_api(domain, api_key):
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {
        "APIKEY": api_key,
        "Accept": "application/json"
    }
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"SecurityTrails API请求失败: {e}")
        return None

def call_zoomeye_api(domain, api_key):
    import base64
    query = f"domain:{domain}"
    qbase64 = base64.b64encode(query.encode('utf-8')).decode('utf-8')
    url = "https://api.zoomeye.org/v2/search"
    headers = {
        "API-KEY": api_key,
        "Content-Type": "application/json"
    }
    try:
        response = requests.post(url, headers=headers, json={"qbase64": qbase64}, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"ZoomEye API请求失败: {e}")
        return None

def call_shodan_api(domain, api_key):
    url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Shodan API请求失败: {e}")
        return None

# 增加详细的错误处理和日志记录功能



try:
    # 示例代码
    pass
except Exception as e:
    logging.error(f"发生错误: {e}")


def run_crtsh(config: Dict, domain: str, output_file: str) -> Set[str]:
    """
    使用crt.sh收集子域名
    :param config: 配置字典
    :param domain: 目标域名
    :param output_file: 输出文件路径
    :return: 收集到的子域名集合
    """
    subdomains = set()
    try:
        import requests
        from bs4 import BeautifulSoup

        url = f"https://crt.sh/?q=%25.{domain}"
        logging.info(f"正在从crt.sh收集子域名...")
        
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        for row in soup.find_all('tr'):
            cells = row.find_all('td')
            if len(cells) >= 5:
                subdomain = cells[4].text.strip()
                if domain in subdomain and validate_domain(subdomain):
                    subdomains.add(subdomain)

        if subdomains:
            logging.info(f"crt.sh收集完成，找到{len(subdomains)}个子域名")
        else:
            logging.warning("crt.sh未找到任何子域名")

    except requests.exceptions.RequestException as e:
        logging.error(f"crt.sh请求失败: {e}")
    except Exception as e:
        logging.error(f"crt.sh收集过程中发生错误: {e}")

    return subdomains


def run_shodan(config: Dict, domain: str, output_file: str) -> Set[str]:
    """
    使用Shodan API收集子域名
    :param config: 配置字典
    :param domain: 目标域名
    :param output_file: 输出文件路径
    :return: 收集到的子域名集合
    """
    subdomains = set()
    try:
        api_key = config['subdomain'].get('shodan_api_key')
        if not api_key:
            logging.error("Shodan API密钥未配置")
            return subdomains

        url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
        logging.info("正在使用Shodan API收集子域名...")
        
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        # 提取子域名
        for record_type in ['a', 'aaaa', 'cname', 'mx', 'ns', 'txt']:
            for record in data.get(record_type, []):
                if 'subdomain' in record and record['subdomain']:
                    full_domain = f"{record['subdomain']}.{domain}"
                    if validate_domain(full_domain):
                        subdomains.add(full_domain)
        
        if subdomains:
            logging.info(f"Shodan收集完成，找到{len(subdomains)}个子域名")
        else:
            logging.warning("Shodan未找到任何子域名")

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            logging.error("Shodan API请求失败: API密钥无效或已过期")
        elif e.response.status_code == 404:
            logging.error("Shodan API请求失败: 未找到该域名的记录")
        else:
            logging.error(f"Shodan API请求失败: {e}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Shodan API请求失败: {e}")
    except Exception as e:
        logging.error(f"Shodan API处理失败: {e}")

    return subdomains

    # 更新show_subdomain_menu函数以包含Shodan选项
    show_subdomain_menu = """
        colors = {
            "option1": "\033[1;32m",  # 绿色加粗
            "option2": "\033[1;33m",  # 黄色加粗
            "option3": "\033[1;34m",  # 蓝色加粗
            "option4": "\033[1;35m",  # 紫色加粗
            "option5": "\033[1;36m",  # 青色加粗
            "option6": "\033[1;37m",  # 白色加粗
            "option0": "\033[1;37m",  # 白色加粗
            "reset": "\033[0m"
        }
        print(f"""
{colors['option1']}[+] 1. 使用subfinder收集子域名{colors['reset']}
{colors['option2']}[2] 使用crt.sh收集子域名{colors['reset']}
{colors['option3']}[3] 使用SecurityTrails API收集{colors['reset']}
{colors['option4']}[4] 一键收集（调用所有方法）{colors['reset']}
{colors['option5']}[5] 使用ZoomEye API收集子域名{colors['reset']}
{colors['option0']}[0] 返回主菜单{colors['reset']}

""")
        """

def run_zoomeye(config: Dict, domain: str, output_file: str) -> Set[str]:
    """
    使用ZoomEye API收集子域名
    :param config: 配置字典
    :param domain: 目标域名
    :param output_file: 输出文件路径
    :return: 收集到的子域名集合
    """
    subdomains = set()
    try:
        import base64

        api_key = config['subdomain'].get('zoomeye_api_key')
        if not api_key:
            logging.error("ZoomEye API密钥未配置")
            return subdomains

        # 准备请求参数
        query = f"domain:{domain}"
        qbase64 = base64.b64encode(query.encode('utf-8')).decode('utf-8')
        payload = {
            "qbase64": qbase64,
            "page": 1,
            "pagesize": 100
        }

        url = "https://api.zoomeye.org/v2/search"
        headers = {
            "API-KEY": api_key,
            "Content-Type": "application/json"
        }

        logging.info("正在使用ZoomEye API收集子域名...")
        total_pages = 1
        current_page = 1

        while current_page <= total_pages:
            try:
                response = requests.post(url, headers=headers, json=payload, timeout=30)
                response.raise_for_status()
                data = response.json()

                # 更新总页数
                if current_page == 1:
                    total_count = data.get('total', 0)
                    total_pages = (total_count + payload['pagesize'] - 1) // payload['pagesize']
                    if total_pages > 1:
                        logging.info(f"找到{total_count}个结果，共{total_pages}页")

                # 处理当前页数据
                for item in data.get('data', []):
                    if 'domain' in item:
                        if validate_domain(item['domain']):
                            subdomains.add(item['domain'])
                    elif 'url' in item:
                        url = item['url']
                        if url.startswith('http://') or url.startswith('https://'):
                            domain_part = url.split('/')[2]
                            if domain_part.endswith(domain) and validate_domain(domain_part):
                                subdomains.add(domain_part)

                if current_page < total_pages:
                    logging.debug(f"正在处理第{current_page}/{total_pages}页")
                    payload['page'] += 1
                    current_page += 1
                else:
                    break

            except requests.exceptions.RequestException as e:
                logging.error(f"处理第{current_page}页时发生错误: {e}")
                break

        if subdomains:
            logging.info(f"ZoomEye收集完成，找到{len(subdomains)}个子域名")
        else:
            logging.warning("ZoomEye未找到任何子域名")

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 402:
            logging.error("ZoomEye API请求失败: 账户余额不足或需要付费订阅")
        elif e.response.status_code == 401:
            logging.error("ZoomEye API请求失败: API密钥无效或已过期")
        else:
            logging.error(f"ZoomEye API请求失败: {e}")
    except Exception as e:
        logging.error(f"ZoomEye API处理失败: {e}")

    return subdomains


def run_securitytrails(config: Dict, domain: str, output_file: str) -> Set[str]:
    """
    使用SecurityTrails API收集子域名
    :param config: 配置字典
    :param domain: 目标域名
    :param output_file: 输出文件路径
    :return: 收集到的子域名集合
    """
    subdomains = set()
    try:
        api_key = config['subdomain'].get('securitytrails_api_key')
        if not api_key:
            logging.error("SecurityTrails API密钥未配置")
            return subdomains

        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {
            "APIKEY": api_key,
            "Accept": "application/json"
        }

        logging.info("正在使用SecurityTrails API收集子域名...")
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()

        data = response.json()
        for sub in data.get('subdomains', []):
            full_domain = f"{sub}.{domain}"
            if validate_domain(full_domain):
                subdomains.add(full_domain)

        if subdomains:
            logging.info(f"SecurityTrails收集完成，找到{len(subdomains)}个子域名")
        else:
            logging.warning("SecurityTrails未找到任何子域名")

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            logging.error("SecurityTrails API密钥无效或已过期")
        elif e.response.status_code == 429:
            logging.error("SecurityTrails API请求超出限制")
        else:
            logging.error(f"SecurityTrails API请求失败: {e}")
    except Exception as e:
        logging.error(f"SecurityTrails API处理失败: {e}")

    return subdomains


def compare_subdomains(domain, output_file):
    pass

    

def call_crt_sh_api(domain):
    api_url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(api_url, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"crt.sh API请求失败: {e}")
        return None

def call_securitytrails_api(domain, api_key):
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {
        "APIKEY": api_key,
        "Accept": "application/json"
    }
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"SecurityTrails API请求失败: {e}")
        return None

def call_zoomeye_api(domain, api_key):
    import base64
    query = f"domain:{domain}"
    qbase64 = base64.b64encode(query.encode('utf-8')).decode('utf-8')
    url = "https://api.zoomeye.org/v2/search"
    headers = {
        "API-KEY": api_key,
        "Content-Type": "application/json"
    }
    try:
        response = requests.post(url, headers=headers, json={"qbase64": qbase64}, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"ZoomEye API请求失败: {e}")
        return None

def call_shodan_api(domain, api_key):
    url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Shodan API请求失败: {e}")
        return None

def compare_subdomains(domain, output_file):
    pass

    