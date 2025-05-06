import requests
from bs4 import BeautifulSoup
import logging
import time
from threading import Semaphore
from collections import deque

# Function to perform ICP query

# 并发控制设置
MAX_CONCURRENT = 20  # 最大并发数
RATE_LIMIT = 40     # 每分钟最大请求数
REQUEST_INTERVAL =1.5 / RATE_LIMIT  # 请求间隔(秒)

# API端点列表
API_ENDPOINTS = [
    "https://cn.apihz.cn/api/wangzhan/icp.php",
    "http://101.35.2.25/api/wangzhan/icp.php",
    "http://124.222.204.22/api/wangzhan/icp.php",
    "http://124.220.49.230/api/wangzhan/icp.php"
]
current_endpoint_index = 0

# 请求队列和信号量
request_queue = deque()
semaphore = Semaphore(MAX_CONCURRENT)
last_request_time = 0

def icp_query(domain):
    global last_request_time
    
    # 获取信号量控制并发
    semaphore.acquire()
    
    try:
        # 计算等待时间
        current_time = time.time()
        elapsed = current_time - last_request_time
        if elapsed < REQUEST_INTERVAL:
            time.sleep(REQUEST_INTERVAL - elapsed)
    except Exception as e:
        logging.error(f"计算请求间隔时发生错误: {e}")
        semaphore.release()
        return

    if elapsed < REQUEST_INTERVAL:
       time.sleep(REQUEST_INTERVAL - elapsed)
    
    global current_endpoint_index
    
    # 请求重试机制
    max_retries = 3
    retry_count = 0
    response = None
    
    while retry_count < max_retries:
        try:
            endpoint = API_ENDPOINTS[current_endpoint_index]
            url = f"{endpoint}?id=10004437&key=89afe5d9cbee98f8fab517307eae0187&domain={domain}"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
                "Accept": "application/json",
            }
            
            # 记录请求时间
            last_request_time = time.time()
            
            # 设置超时时间为5秒
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                break
                
            logging.warning(f"请求端点 {endpoint} 失败，状态码: {response.status_code}, 尝试 {retry_count+1}/{max_retries}")
            
        except (requests.exceptions.RequestException, requests.exceptions.Timeout) as e:
            logging.warning(f"请求端点 {API_ENDPOINTS[current_endpoint_index]} 失败: {str(e)}, 尝试 {retry_count+1}/{max_retries}")
            
        finally:
            # 切换到下一个端点
            current_endpoint_index = (current_endpoint_index + 1) % len(API_ENDPOINTS)
            retry_count += 1
            if retry_count < max_retries:
                time.sleep(1)  # 重试前等待1秒
    
    if not response or response.status_code != 200:
        logging.error(f"所有端点请求失败，最后状态码: {response.status_code if response else '无响应'}")
        semaphore.release()
        return {"code": 500, "msg": "所有端点请求失败"}

    data = response.json()
    semaphore.release()

    # 提取所需的备案信息
    code = data.get("code", 400)
    msg = data.get("msg", "")
    td = data.get("td", "")
    registration_type = data.get("type", "")
    icp_number = data.get("icp", "")
    company_name = data.get("unit", "")
    website_name = data.get("domain", "")
    registration_time = data.get("time", "")

    return {
        "code": code,
        "msg": msg,
        "td": td,
        "registration_type": registration_type,
        "icp_number": icp_number,
        "company_name": company_name,
        "website_name": website_name,
        "registration_time": registration_time
    }

# Function to read domains from a txt file
def read_domains_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            domains = file.read().splitlines()
            return domains
    except Exception as e:
        logging.error(f"Error reading file: {e}")
        return []

# Example usage
if __name__ == "__main__":
    file_path = input("请输入域名或包含域名的txt文件路径: ")
    if file_path.endswith('.txt'):
        domains = read_domains_from_file(file_path)
    else:
        domains = [file_path]

    for domain in domains:
        result = icp_query(domain)
        if result:
            print("\n备案信息:\n")
            print("公司名称: {:<30} 备案号: {:<20}".format(result['company_name'], result['icp_number']))
            print("网站名称: {:<30} 注册类型: {:<10}".format(result['website_name'], result['registration_type']))
            print("注册时间: {:<30}\n".format(result['registration_time']))
        else:
            print(f"域名 {domain} 查询失败")

# Function to save selected ICP info to file
def save_icp_info(icp_info_list, selected_indices):
    try:
        with open('results/icp/selected_icp_info.txt', 'a', encoding='utf-8') as f:
            for idx in selected_indices:
                info = icp_info_list[idx]
                f.write(f"主体: {info['company_name']}, 备案号: {info['icp_number']}, 域名: {info['website_name']}, 审核时间: {info['registration_time']}\n")
        logging.info("已保存选定的备案信息到results/icp/selected_icp_info.txt")
    except Exception as e:
        logging.error(f"保存备案信息时出错: {e}")

# Function to run the query based on config
def run(config):
    file_path = input("请输入域名或包含域名的txt文件路径: ")
    if file_path.endswith('.txt'):
        domains = read_domains_from_file(file_path)
    else:
        domains = [file_path]

    icp_info_list = []
    for domain in domains:
        if not domain:
            logging.error("未输入域名信息")
            continue
        
        icp_info = icp_query(domain)
        if icp_info:
            if not hasattr(run, 'last_icp_info') or run.last_icp_info != icp_info:
                logging.info(f"主体性质: {icp_info['registration_type']}, 备案号: {icp_info['icp_number']}, 主体: {icp_info['company_name']}, 域名: {icp_info['website_name']}, 审核时间: {icp_info['registration_time']}")
                run.last_icp_info = icp_info
                icp_info_list.append(icp_info)
        else:
            logging.error(f"未能获取域名 {domain} 的备案信息")
    
    if icp_info_list:
        print("\n查询完成，请选择要保存的主体(输入序号，多个用逗号分隔):")
        for i, info in enumerate(icp_info_list):
            print(f"[{i}] {info['company_name']} ({info['website_name']})")
        
        while True:
            try:
                selection = input("选择要保存的主体(输入序号，多个用逗号分隔，或输入q退出): ")
                if selection.lower() == 'q':
                    break
                selected_indices = [int(idx.strip()) for idx in selection.split(',')]
                if all(0 <= idx < len(icp_info_list) for idx in selected_indices):
                    save_icp_info(icp_info_list, selected_indices)
                    break
                else:
                    print("输入无效，请重新输入")
            except ValueError:
                print("输入无效，请输入数字或q退出")