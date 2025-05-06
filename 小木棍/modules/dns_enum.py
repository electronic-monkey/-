# DNS扫描模块
import dns.resolver
import dns.query
import dns.zone
import logging
from typing import List, Dict
from colorama import Fore, Style

def query_dns_records(domain: str, record_type: str = 'A') -> List[str]:
    """
    查询指定域名的DNS记录
    :param domain: 要查询的域名
    :param record_type: 记录类型(A, MX, NS, TXT等)
    :return: 查询结果列表
    """
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(r) for r in answers]
    except dns.resolver.NoAnswer:
        logging.warning(f"{domain} 没有{record_type}记录")
        return []
    except dns.resolver.NXDOMAIN:
        logging.warning(f"{domain} 域名不存在")
        return []
    except Exception as e:
        logging.error(f"查询{domain}的{record_type}记录时出错: {e}")
        return []

def check_axfr(domain: str, nameserver: str) -> bool:
    """
    检测DNS区域传输漏洞(AXFR)
    :param domain: 要检测的域名
    :param nameserver: DNS服务器地址
    :return: 是否存在漏洞
    """
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
        if zone:
            logging.warning(f"{Fore.RED}{domain} 存在DNS区域传输漏洞{Style.RESET_ALL}")
            return True
    except Exception:
        pass
    return False

def run(config: Dict) -> None:
    """
    执行DNS扫描
    :param config: 配置参数
    """
    targets = []
    
    # 用户输入目标域名
    input_target = input("请输入要扫描的域名(多个域名用逗号分隔)或文件路径: ").strip()
    
    if input_target.endswith('.txt'):
        # 如果是文件路径，则读取文件内容
        try:
            with open(input_target, 'r', encoding='utf-8') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logging.error(f"域名文件不存在: {input_target}")
            return
        except Exception as e:
            logging.error(f"读取域名文件失败: {e}")
            return
    else:
        # 处理逗号分隔的多个域名
        targets = [t.strip() for t in input_target.split(',') if t.strip()]
    
    if not targets:
        logging.error("未提供有效的扫描目标")
        return
    
    logging.info(f"开始DNS扫描: {len(targets)}个目标")
    
    for target in targets:
        try:
            # 查询常见DNS记录
            record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME']
            results = {}
            
            for rtype in record_types:
                records = query_dns_records(target, rtype)
                if records:
                    results[rtype] = records
            
            # 检测AXFR漏洞
            nameservers = query_dns_records(target, 'NS')
            for ns in nameservers:
                if check_axfr(target, ns):
                    results['AXFR_VULNERABLE'] = True
                    print(f"{Fore.RED}警告: {target} 存在DNS域传送漏洞!{Style.RESET_ALL}")
            
            # 保存结果
            if results:
                logging.info(f"{target} 扫描完成，结果: {results}")
            else:
                logging.warning(f"{target} 未获取到任何DNS记录")
        except Exception as e:
            logging.error(f"扫描{target}时出错: {e}")
    
    # 查询常见DNS记录
    record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME']
    results = {}
    
    for rtype in record_types:
        records = query_dns_records(target, rtype)
        if records:
            results[rtype] = records
    
    # 检测AXFR漏洞
    nameservers = query_dns_records(target, 'NS')
    for ns in nameservers:
        if check_axfr(target, ns):
            results['AXFR_VULNERABLE'] = True
    
    # 保存结果
    if results:
        logging.info(f"DNS扫描完成，结果: {results}")
    else:
        logging.warning("未获取到任何DNS记录")