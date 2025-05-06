import time
import yaml
import importlib
from pathlib import Path
import logging
from typing import Dict, Optional
from colorama import init, Fore, Style

init(autoreset=True)

class ConfigManager:
    def __init__(self):
        self.config_file = 'config.yaml'
        self.config: Optional[Dict] = None

    def load_config(self) -> Optional[Dict]:
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
                logging.info("配置文件加载成功")
                return self.config
        except FileNotFoundError:
            logging.error(f"配置文件{self.config_file}不存在，请先创建配置文件")
            return None
        except yaml.YAMLError as e:
            logging.error(f"配置文件格式错误: {e}")
            return None
        except Exception as e:
            logging.error(f"加载配置文件时发生错误: {e}")
            return None

# 主菜单
def show_menu():
    colors = {
        "title": "\033[1;36m",  # 青色加粗
        "option1": "\033[1;32m",  # 绿色加粗
        "option2": "\033[1;33m",  # 黄色加粗
        "option3": "\033[1;34m",  # 蓝色加粗
        "option4": "\033[1;35m",  # 紫色加粗
        "option0": "\033[1;37m",  # 白色加粗
        "border": "\033[1;36m",  # 青色加粗
        "reset": "\033[0m"
    }
    
    print(f"""
{colors['title']}                      __------__ 
                     /~          ~\ 
                    |    //^\\//^\|         Oh..My great god ...     
                  /~~\  ||  o| |o|:~\       Please grant me many many 
                 | |6   ||___|_|_||:|    /  bananas .. I want to give them 
                  \__.  /      o  \/'       to my dear XiaoMei, then she will 
                   |   (       O   )        agree to marry me!! 
          /~~~~\    `\  \         / 
         | |~~\ |     )  ~------~`\ 
        /' |  | |   /     ____ /~~~)\ 
       (_/'   | | |     /'    |    ( | 
              | | |     \    /   __)/ \ 
              \  \ \      \/    /' \   `\ 
                \  \|\        /   | |\___| 
                  \ |  \____/     | | 
                  /^~>  \        _/ < 
                 |  |         \       \ 
                 |  | \        \        \ 
                 -^-\  \       |        ) 
                      `\_______/^\______/{colors['reset']}
{colors['option1']}[1] 子域名收集{colors['reset']}
{colors['option2']}[2] DNS扫描{colors['reset']}
{colors['option3']}[3] 备案查询{colors['reset']}
{colors['option4']}[4] 端口扫描{colors['reset']}
{colors['option0']}[0] 退出{colors['reset']}
{colors['border']}══════════════════════════════{colors['reset']}
""")

# 初始化日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 主函数
class ResultsManager:
    def __init__(self):
        self.results_dir = Path('results')
        self.subdirs = ['subdomains', 'dns', 'icp', 'ports', 'fingerprints']

    def initialize_directories(self) -> bool:
        try:
            self.results_dir.mkdir(exist_ok=True)
            for subdir in self.subdirs:
                (self.results_dir / subdir).mkdir(exist_ok=True)
            logging.info("结果目录初始化成功")
            return True
        except Exception as e:
            logging.error(f"创建目录时发生错误: {e}")
            return False

class ModuleRunner:
    def __init__(self, config: Dict):
        self.config = config
        self.modules = {
            '1': ('modules.subdomain', '子域名收集'),
            '2': ('modules.dns_enum', 'DNS扫描'),
            '3': ('modules.icp_query', '备案查询'),
            '4': ('modules.port_scan', '端口扫描'),
            '5': ('modules.zoomeye', 'ZoomEye查询')
        }

    def run_module(self, choice: str) -> None:
        if choice not in self.modules:
            logging.warning("无效选择，请重新输入")
            return

        module_path, module_name = self.modules[choice]
        try:
            logging.info(f"正在加载模块: {module_name}")
            start_time = time.time()
            module = importlib.import_module(module_path)
            module.run(self.config)
            elapsed_time = time.time() - start_time
            logging.info(f"模块 {module_name} 执行完成，耗时: {elapsed_time:.2f}秒")
        except ImportError as e:
            logging.error(f"模块 {module_name} 加载失败: {e}")
        except Exception as e:
            logging.error(f"运行模块 {module_name} 时发生错误: {e}")

def main():
    # 初始化日志配置
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('scanner.log', encoding='utf-8')
        ]
    )

    # 初始化结果目录
    results_manager = ResultsManager()
    if not results_manager.initialize_directories():
        return

    # 加载配置
    config_manager = ConfigManager()
    config = config_manager.load_config()
    if not config:
        return

    # 初始化模块运行器
    module_runner = ModuleRunner(config)

    while True:
        show_menu()
        try:
            choice = input(f"{Fore.CYAN}请选择功能模块(0-5): {Style.RESET_ALL}")
            logging.info(f"用户选择了功能模块: {choice}")

            if choice == '0':
                logging.info("程序退出")
                break
            
            module_runner.run_module(choice)

        except KeyboardInterrupt:
            logging.info("用户中断程序执行")
            break
        except Exception as e:
            logging.error(f"发生未预期的错误: {e}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.critical(f"程序发生严重错误: {e}")