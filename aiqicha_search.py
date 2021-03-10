import os, json, time,re,tldextract,mmh3,codecs,socket,socks
import requests
from requests.adapters import HTTPAdapter
from lxml import etree
import warnings
warnings.filterwarnings(action='ignore')

headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'}



socks.set_default_proxy(socks.SOCKS5, "ip", 16000)
socket.socket = socks.socksocket


t0 = time.time()
path_file_list = []
kw_list = []
# 有代理池的把use_proxy的值改成1
use_proxy = 0
#provs参数为查询页面中的省份地区
provs = [110000, 120000, 130000, 140000, 150000, 210000, 220000, 230000, 310000, 320000, 330000, 340000, 350000, 360000,
		 370000, 410000, 420000, 430000, 440000, 450000, 460000, 500000, 510000, 520000, 530000, 540000, 610000, 620000,
		 630000, 640000, 650000]
#rcl参数为查询页面中的注册资本
rcl = [1, 2, 3, 4, 5]
#sy参数是成立年限中的自定义010-2011', '2011-2012', '2012-2013', '2013-2014', '2014-2015', '2015-2016',
# 	  '2016-2017', '2017-2018', '2018
# # sy = ['1990-2005', '2005-2010', '2-2019', '2019-2020', '2020-2021', '2021-2022']
sy = ['level1','level2','level3','level4','level5']#使用默认值的参数
#wdl是行业分类，这个参数还没有用到，如果后续测试二次拆分检索数据量还比较大就会再增加循环
wdl = 'ABCDEFGHIJKLMNOPQRST'

#get_proxy函数为代理池配置函数，req_get_proxy函数为切换IP函数，代理池的开关变量为use_proxy
#如果有代理池，自己配置代理池
def get_proxy():
    try:
        response = requests.get('ip')
        if response.status_code == 200:
            return response.text
    except ConnectionError:
        return None

#代理切换函数
def req_get_proxy(url):
	global line
	# 代理不可用则直接换一个代理ip
	try:
		proxy = {
			'http': line,
			'https': line
		}
		resp = requests.get(url, headers=headers, timeout=10,proxies=proxy,verify=False)#如果启用代理池，需要在这里添加proxy
		print(resp)
	except:
		line = get_proxy()
		resp = req_get(url)
	# 服务器禁用该代理ip，则再换一个
	if 'check' in resp.url:
		print('[+] IP已经失效，正在更换IP')
		line = get_proxy()
		resp = req_get(url)
	return resp

#处理查询速度过快被封禁情况，1分钟后自动解除
def req_get(url):
	# 每次禁用ip，1min后会解封
	global t0
	try:
		resp = requests.get(url, headers=headers, timeout=10,verify=False)
	except:
		resp = req_get(url)
	print(url)
	print(resp.url)
	if 'check' in resp.url:
		print('[+] 检测到验证码，请等待一分钟')
		t1 = time.time()
		dt = 60 - t1 + t0
		dtt = dt if dt >= 0 else 0
		time.sleep(dtt)
		# time.sleep(1)
		resp = req_get(url)
		t0 = time.time()
	return resp

def write_comp(resp,path_file):
	# 直接存json格式
	page_data = re.findall('pageData = ({.*})', resp.text)
	if len(page_data) > 0:
		page_data = page_data[0]
		jd = json.loads(page_data)
		with open(path_file,'a+',encoding='utf-8') as out_file:
			for comp in jd['result']['resultList']:
				print(comp['pid'])
				out_file.write(comp['pid'] + '\n')

def req_ico_hash(url):
	try:
		s = requests.Session()  # 设置会话
		s.mount('http://', HTTPAdapter(max_retries=1))  # 设置http协议最大重试次数
		url = 'http://' + url
		html = s.get(url, headers=headers, timeout=6, verify=False)
		check = True
	except:
		check = None
	if check == None:
		try:
			s = requests.Session()  # 设置会话
			s.mount('https://', HTTPAdapter(max_retries=1))  # 设置http协议最大重试次数
			url = 'https://' + url
			html = s.get(url, headers=headers, timeout=6, verify=False)
			check = True
		except:
			check = None
	if check == True:
		# html_sutatus = html.status_code
		# print(html_sutatus)
		parseHtml = etree.HTML(html.text)
		ico_url = parseHtml.xpath('//link/@href')
		if len(ico_url) != 0:
			for i in ico_url:
				if ".ico" in i:
					print(url + '/' + i)
					_icon = mmh3.hash(codecs.lookup('base64').encode(requests.get(url + '/' + i,verify=False).content)[0])
					return _icon#找出hash值，直接退出函数，返回hash值
			ico_check = None
			# return None#循环结束后依然没有找到ico
		else:
			ico_check = None
			# return None#ico_url的长度是0，没有匹配到link标签
		if ico_check == None:
			ico_rasp = s.get(url + '/favicon.ico', headers=headers, timeout=6, verify=False)
			if ico_rasp.status_code == 200:
				_icon = mmh3.hash(codecs.lookup('base64').encode(requests.get(url + '/favicon.ico',verify=False).content)[0])
				return _icon
	else:
		return None#请求了两次依然是请求异常，退出函数

def search_pid(kw):
	#生成keyword和日期拼接的文件名称
	filename = kw + '%s.txt' % time.strftime("-%Y-%m-%d-%H-%M", time.localtime(time.time()))
	path_file = os.path.join(os.getcwd(), 'data_log', filename)
	path_file_list.append(str(path_file))#记录下每次查询时的关键词
	print(path_file_list)
	#第一次请求接口，获取数据
	url0 = 'https://aiqicha.baidu.com/s?q=%s&f={"openStatus":"开业","searchtype":1}' % (kw)
	resp = req_get(url0)
	if len(re.findall('pageData = ({.*})', resp.text)) >= 1:
		page_data = re.findall('pageData = ({.*})', resp.text)[0]#使用正则匹配到返回的json数据
	else:
		return None
	jd = json.loads(page_data)#json.loads()将字符串类型转化成字典类型
	tnum = int(jd['result']['totalNumFound'])#提取出返回的数据总量
	print('[+] 初次请求获取数量' + str(tnum)+ '\n请求地址：' + url0)
	if tnum <= 1000 and tnum > 0:
		page = tnum // 10 + 1
		for p in range(page):
			try:
				print(url0 + '&p=%d' % (p + 1))
				resp = req_get(url0 + '&p=%d' % (p + 1))
				write_comp(resp, path_file)
			except Exception as e:
				with open('error.txt','a+',encoding='utf-8') as f:
					f.write(e+'\n')
				line = get_proxy()
				resp = req_get(url0 + '&p=%d' % (p + 1))
				write_comp(resp, path_file)
				# line = get_proxy()#这个参数是作用于use_proxy的值为1时，使用代理池更换IP，但get_proxy函数我写的有些问题，代理池如果没开，请求代理池时会出现异常，所以先暂时注释
				# resp = req_get(url0 + '&p=%d' % (p + 1))
				# write_comp(resp, path_file)
	elif tnum > 1000:
		print('[+] 返回数据大于1000，正在进行第一次拆分检索')
		for pr in provs:
			for lv in rcl:
				url0 = 'https://aiqicha.baidu.com/s?q=%s&f={"openStatus":"开业","searchtype":1,"provinceCode":"%d","regCapLevel":"level%d"}' % (kw, pr, lv)
				print('[+] 请求地址： ' + url0)
				resp = req_get(url0)
				if len(re.findall('pageData = ({.*})', resp.text)) >= 1:
					page_data = re.findall('pageData = ({.*})', resp.text)[0]#这里可能会出现下标越界，暂时先保留
				else:
					with open('error.txt','a+',encoding='utf-8') as f:
						f.write(url0 + '\n')
					print('[+] 政治匹配页数出现异常，跳过此次循环！')
					continue
				jd = json.loads(page_data)
				tnum = int(jd['result']['totalNumFound'])
				print('[+] 第一次拆分检索，省份地区参数'+ str(pr), '注册资本参数：'+ str(lv),'获取数量'+ str(tnum))
				if tnum <= 1000:
					page = tnum // 10 + 1
					for p in range(page):
						try:
							resp = req_get(url0 + '&p=%d' % (p + 1))
							write_comp(resp,path_file)
						except Exception as e:
							with open('error.txt', 'a+', encoding='utf-8') as f:
								f.write(e+'\n')
							line = get_proxy()
							resp = req_get(url0 + '&p=%d' % (p + 1))
							write_comp(resp, path_file)
				# 大于1000条，进行拆分检索
				elif tnum > 1000 and tnum > 0:
					print('[+] 第一次拆分检索后返回数据仍大于1000，正在进行第二次拆分检索')
					for yr in sy:
						url = 'https://aiqicha.baidu.com/s?q=%s&f={"openStatus":"开业","searchtype":1,"provinceCode":"%d","regCapLevel":"level%d","startYear":"%s"}' % (kw, pr, lv, yr)
						try:
							resp = req_get(url)
							write_comp(resp,path_file)

						except Exception as e:
							with open('error.txt', 'a+', encoding='utf-8') as f:
								f.write(e+'\n')
							line = get_proxy()
							resp = req_get(url0 + '&p=%d' % (p + 1))
							write_comp(resp, path_file)
						if len(re.findall('pageData = ({.*})', resp.text)) >= 1:
							page_data = re.findall('pageData = ({.*})', resp.text)[0]
						else:
							with open('error.txt', 'a+', encoding='utf-8') as f:
								f.write(url0 + '\n')
							print('[+] 政治匹配页数出现异常，跳过此次循环！')
							continue
						jd = json.loads(page_data)
						tnum = int(jd['result']['totalNumFound'])
						# print(tnum, ar)
						if tnum // 10 > 1:
							page = tnum // 10 + 1 if tnum < 1000 else 101
							for p in range(1, page):
								try:
									resp = req_get(url + '&p=%d' % (p + 1))
									write_comp(resp,path_file)
								except Exception as e:
									with open('error.txt', 'a+', encoding='utf-8') as f:
										f.write(e+'\n')
									line = get_proxy()
									resp = req_get(url0 + '&p=%d' % (p + 1))
									write_comp(resp, path_file)
						# 还大于1000条的话，记录该条信息，也可以根据其他筛选条件继续拆分检索
						if tnum > 1000:
							print('[+] 结果仍然大于1000，不再拆分，保存结果到big_url.txt中')
							with open('big_url.txt', 'a+', encoding='utf-8') as f:
								f.write(url+'\n')

def result_search(file_name):
	print(file_name)
	j = 0
	# 加载search_result爬到的数据
	with open(file_name, 'r', encoding='utf-8') as f:
		ac = f.readlines()
		total = len(ac)
	keyword = kw_list.pop(0)
	filename = keyword + '%s.txt' % time.strftime("-%Y-%m-%d-%H-%M", time.localtime(time.time()))
	#文件路径
	path_file = os.path.join(os.getcwd(), 'result', filename)
	all_search_path = os.path.join(os.getcwd(), 'fofa_search', 'all_search',filename)  # host、domain、cert的语法写在同一个文件里
	title_path = os.path.join(os.getcwd(), 'fofa_search', 'title', filename)  # 因为通过title去搜索，出现的结果会比较模糊，把title单独生成一个文件
	domain_path = os.path.join(os.getcwd(), 'fofa_search', 'all_domain', filename)  # 记录所有主域名，方便后续子域名爆破
	all_title_path = os.path.join(os.getcwd(), 'fofa_search', 'all_title', filename)  # 记录所有公司的名称，方便后续处理
	all_subdomain_path = os.path.join(os.getcwd(), 'fofa_search', 'all_subdomain', filename)  # 记录所有查询到的公司域名
	#首先对关键词进行fofa的语句生成
	with open(all_search_path,'a+',encoding='utf-8') as f:
		f.write('body="{body} 版权所有" && country="CN" && region !="HK" && region != "MO"'.format(body = keyword) + '\n' +
				'body="版权所有 {body}"&& country="CN" && region !="HK" && region != "MO"'.format(body = keyword) + '\n' +
				'body="{body} 网站运营" && country="CN" && region !="HK" && region != "MO"'.format(body=keyword) + '\n' +
				'body="网站运营 {body}"&& country="CN" && region !="HK" && region != "MO"'.format(body=keyword) + '\n' +
				'title="{title}" && country="CN" && region !="HK" && region != "MO"'.format(title = keyword)+ '\n')
	for pid in  open(file_name, 'r', encoding='utf-8'):
		pid = pid.strip()
		rsp = req_get('https://aiqicha.baidu.com/detail/basicAllDataAjax?pid=%s' % (pid))
		jd = json.loads(rsp.text)
		if '系统异常' in jd['msg']:
			with open('error_pid.txt', 'a+', encoding='utf-8')as f:
				f.write(pid +'\n')
		else:
			j += 1
			req_website = str(jd['data']['basicData']['website'])
			req_entName = str(jd['data']['basicData']['entName'])
			req_email = str(jd['data']['basicData']['email'])
			req_telephone = str(jd['data']['basicData']['telephone'])
			req_legalPerson = str(jd['data']['basicData']['legalPerson'])
			result_content = """
{j}/{total}
爱企查： https://aiqicha.baidu.com/company_detail_{pid}
公司域名： {req_website}
公司名称： {req_entName}
邮箱： {req_email}
电话： {req_telephone}
法人： {req_legalPerson}
							""".format(j=j,total=total,pid=pid, req_website=req_website, req_entName=req_entName, req_email=req_email,
									   req_telephone=req_telephone, req_legalPerson=req_legalPerson)
			print(result_content)
			with open(path_file, 'a+', encoding='utf-8') as f:#写入查询到的所有记录
				f.write(result_content+'\n')
			if req_website != 'None':#如果通过接口获取的域名不为None
				with open(all_subdomain_path,'a+',encoding='utf-8') as f:
					f.write(req_website + '\n')
				#访问公司域名，获取ico的hash值
				_icon = req_ico_hash(req_website)#此时req_website的值还没有被拆分，获取ico的hash值
				if _icon != None:  # 如果查找到图标的hash值
					with open(all_search_path, 'a+', encoding='utf-8') as f:#
						f.write('icon_hash="{_icon}" && country="CN" && region !="HK" && region != "MO"'.format(_icon=_icon) + '\n')
				tld = tldextract.extract(req_website)#把域名拆分为3部分
				req_website = tld[1] + '.' + tld[2]#提取出主域名
				print(req_website)
				website_fofa = 'domain="{domain}" && country="CN" && region !="HK" && region != "MO"'.format(domain=req_website)
				host_fofa = 'host="{host}" && country="CN" && region !="HK" && region != "MO"'.format(host=req_website)
				cert_fofa = 'cert="{cert}" && country="CN" && region !="HK" && region != "MO"'.format(cert=req_website)
				with open(all_search_path, 'a+', encoding='utf-8') as f:
					f.write(website_fofa + '\n' + host_fofa + '\n' + cert_fofa + '\n')
				with open(domain_path,'a+',encoding='utf-8') as f:
					f.write(req_website + '\n')

			if req_entName != 'None':
				with open(all_title_path,'a+',encoding='utf-8') as f:#记录下所有公司名称
					f.write(req_entName + '\n')
				req_entName = req_entName.replace('有限公司','').replace('分公司','').replace('分部','')
				entName_fofa = 'title="{title}" && country="CN" && region !="HK" && region != "MO"'.format(title=req_entName)
				body_fofa_1 = 'body="{body} 版权所有" && country="CN" && region !="HK" && region != "MO"'.format(body=req_entName)
				body_fofa_2 = 'body="版权所有 {body}"&& country="CN" && region !="HK" && region != "MO"'.format(body=req_entName)
				with open(all_search_path, 'a+', encoding='utf-8') as f:#记录下body的搜索结果，查找版权所有准确率还算比较高，所以记录在这里
					f.write(body_fofa_1 + '\n' + body_fofa_2 + '\n')
				with open(title_path,'a+',encoding='utf-8') as f:#基于title的搜索比较模糊，较大几率查找到无关资产，所以单独记录
					f.write(entName_fofa + '\n')


if __name__ == '__main__':
	if use_proxy == 1:
		line = get_proxy()
		print(line)
		req_get = req_get_proxy
	for kw in open('keyword.txt','r',encoding='utf-8'):
		kw = kw.strip()
		print(kw)
		kw_list.append(kw)
		search_pid(kw)
	for file_name in path_file_list:
		result_search(file_name)