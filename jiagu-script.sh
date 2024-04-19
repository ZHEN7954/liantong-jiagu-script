#!/bin/bash

echo " "
echo "##########################################################################"
echo "#                                                                        #"
echo "#                               主机安全检测                             #"
echo "#                                                                        #"
echo "##########################################################################"
echo " "
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>系统基本信息<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
hostname=$(uname -n)
system=$(cat /etc/os-release | grep "^NAME" | awk -F\" '{print $2}')
version=$(cat /etc/redhat-release | awk '{print $4$5}')
kernel=$(uname -r)
platform=$(uname -p)
address=$(ip addr | grep inet | grep -v "inet6" | grep -v "127.0.0.1" | awk '{ print $2; }' | tr '\n' '\t' )
cpumodel=$(cat /proc/cpuinfo | grep name | cut -f2 -d: | uniq)
cpu=$(cat /proc/cpuinfo | grep 'processor' | sort | uniq | wc -l)
machinemodel=$(dmidecode | grep "Product Name" | sed 's/^[ \t]*//g' | tr '\n' '\t' )
date=$(date)

echo "主机名:           $hostname"
echo "系统名称:         $system"
echo "系统版本:         $version"
echo "内核版本:         $kernel"
echo "系统类型:         $platform"
echo "本机IP地址:       $address"
echo "CPU型号:          $cpumodel"
echo "CPU核数:          $cpu"
echo "机器型号:         $machinemodel"
echo "系统时间:         $date"
echo " "
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>资源使用情况<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
summemory=$(free -h |grep "Mem:" | awk '{print $2}')
freememory=$(free -h |grep "Mem:" | awk '{print $4}')
usagememory=$(free -h |grep "Mem:" | awk '{print $3}')
uptime=$(uptime | awk '{print $2" "$3" "$4" "$5}' | sed 's/,$//g')
loadavg=$(uptime | awk '{print $9" "$10" "$11" "$12" "$13}')

echo "总内存大小:           $summemory"
echo "已使用内存大小:       $usagememory"
echo "可使用内存大小:       $freememory"
echo "系统运行时间:         $uptime"
echo "系统负载:             $loadavg"


check_null_passwd_uid_0(){
  echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>密码为空 uid=0 看回显判断<<<<<<<<<<<<<<<<<<<<<<<"
  nullpasswd=$(/bin/cat /etc/shadow | /bin/awk -F: '($2 == "" ) { print "user " $1 " does not have a password "}')
  echo "空密码用户:    $nullpasswd"
  uid0user=$(awk -F: '($3 == 0) {print}' /etc/passwd)
  echo "uid=0用户：    $uid0user"
}


centos7_add_password_policy(){
  echo ">>>>>>>>>>>>>>>>>>>>>>centos7添加密码策略<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
  cp /etc/security/pwquality.conf{,.bak}
#  cat /etc/security/pwquality.conf | grep -e "remember\|deny\|difok\|minlen\|lcredit\|ucredit\|dcredit\|ocredit\|unlock_time" | grep -v '#'
  sed -i 's/^\([^#]\)/# \1/g' /etc/security/pwquality.conf
  cat >> /etc/security/pwquality.conf << EOF
remember = 5
deny = 5
difok = 5
minlen = 9
lcredit = -1 
ucredit = -1 
dcredit = -1 
ocredit = -1  
unlock_time = 900
EOF
  cat  /etc/security/pwquality.conf | grep -v '#'
}

check_wheel(){
  echo ">>>>>>>>>>>>>>>>>>>>>>>>检查wheel有无app_999<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
  getent group wheel | grep 'app_999'  > /dev/null
  if [ $? -ne 0 ];then
    usermod -G wheel app_999
    echo "app_999 add to wheel group"
  else
    getent group wheel | grep 'app_999'
  fi
    echo ">>>>>>>>>>>>>>>>><检查/etc/pam.d/su 已添加wheel<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
  cp /etc/pam.d/su{,.bak}
  if grep -q "group=wheel" /etc/pam.d/su; then
      echo 'youle '
  else
      sed -i 's/#auth\s\+required\s\+pam_wheel\.so\s\+use_uid/auth\t\trequired\tpam_wheel.so group=wheel/'  /etc/pam.d/su
      echo 'yi tianjia'
  fi

  cat /etc/pam.d/su
}



check_vsftp_service(){
  echo ">>>>>>>>>>>>>>>>>>>>>>>检查vsftp服务<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
  # 检查是否安装了 vsftpd
  if ! command -v vsftpd &> /dev/null; then
      echo "vsftpd 未安装"
  else
      echo "vsftpd 已安装，请配置限制条件"
      if grep -q "^root$" /etc/vsftpd/ftpusers; then
      	echo 'root alread no'
      else
      	echo "root" >> /etc/vsftpd/ftpusers 
      	echo 'root alread add'
      fi
      if grep -q "^anon_umask=022$" /etc/vsftpd/vsftpd.conf && grep -q "^local_umask=022$" /etc/vsftpd/vsftpd.conf; then
      echo "已经存在 anon_umask=022 和 local_umask=022 两行"
      grep -E '^(anon|local)_umask=022$' /etc/vsftpd/vsftpd.conf | grep -v '#'
  		else
  		    { grep -q "^anon_umask=022$" /etc/vsftpd/vsftpd.conf || echo "anon_umask=022"; grep -q "^local_umask=022$" /etc/vsftpd/vsftpd.conf || echo "local_umask=022"; } | sudo tee -a /etc/vsftpd/vsftpd.conf >/dev/null
  		    echo "已添加缺失的行到 /etc/vsftpd/vsftpd.conf"
  		    grep -E '^(anon|local)_umask=022$' /etc/vsftpd/vsftpd.conf | grep -v '#'
  				# 重启 vsftpd 服务
  				systemctl restart vsftpd
  				if [ $? -eq 0 ]; then
  					    echo "vsftpd 服务已成功重启"
  					else
  					    echo "重启 vsftpd 服务时出现错误请检查"
  				fi
  		fi
  fi
}


add_sysfile_authority(){
  echo ">>>>>>>>>>>>>>>>>>>>>>>>>检查系统文件权限<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
  chmod 644 /etc/passwd
  chmod 400 /etc/shadow
  chmod 644 /etc/group
  chmod 600 /var/log/messages
  chmod 644 /var/log/dmesg
  chmod 600 /var/log/maillog
  chmod 600 /var/log/secure 
  chmod 664 /var/log/wtmp
  chmod 600 /var/log/cron

  ls -l /etc/passwd
  ls -l /etc/shadow
  ls -l /etc/group
  ls -l /var/log/messages
  ls -l /var/log/dmesg
  ls -l /var/log/maillog
  ls -l /var/log/secure 
  ls -l /var/log/wtmp
  ls -l /var/log/cron
}

ssh_config_reinforce(){
  echo ">>>>>>>>>>>>>>>>>>>>>>>ssh 加固<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
  cp /etc/ssh/sshd_config{,.bak}
  # 取消 LogLevel INFO 参数的注释
  sed  -i '/^#LogLevel INFO/s/^#//' /etc/ssh/sshd_config
  cat /etc/ssh/sshd_config | grep evel

  #原有的全注释
  sed -i '/^ClientAliveInterval /s/^/#/' /etc/ssh/sshd_config
  sed -i '/^ClientAliveCountMax /s/^/#/' /etc/ssh/sshd_config
  sed -i '/^MaxAuthTries /s/^/#/' /etc/ssh/sshd_config
  sed -i '/^IgnoreRhosts /s/^/#/' /etc/ssh/sshd_config
  sed -i '/^HostbasedAuthentication /s/^/#/' /etc/ssh/sshd_config
  sed -i '/^PermitEmptyPasswords /s/^/#/' /etc/ssh/sshd_config
  sed -i '/^PermitRootLogin /s/^/#/' /etc/ssh/sshd_config
  sed -i '/^X11Forwarding /s/^/#/' /etc/ssh/sshd_config
  #全部一次性追加
  cat >> /etc/ssh/sshd_config << EOF
ClientAliveInterval 600
ClientAliveCountMax 2
MaxAuthTries 4
IgnoreRhosts yes
HostbasedAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
X11Forwarding no 
EOF
  tail -n 10 /etc/ssh/sshd_config
  systemctl restart sshd
  systemctl status  sshd
}


check_telnet_service(){
  echo ">>>>>>>>>>>>>>>>>>>>>>>检查是否开启了Telnet-Server服务<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
  if ss -tnlp  | grep 23; then
    echo ">>>Telnet-Server服务已开启"
  else
    echo "Telnet-Server服务未开启--------[无需调整]"
  fi
}

config_log(){
  echo ">>>>>>>>>>>>>>>>>>>>>>>配置日志服务<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
  #=========rsylog
  systemctl enable rsyslog
  echo "------------检查rsyslog日志配置-------------------"
  cat /etc/rsyslog.conf | grep -e "secure\|cron"  | grep -v '#'
  
  
  #======lograte
  echo ">>>>>>>>>>>>>>>>>>>>>>>配置lograte日志切割<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
  cp /etc/logrotate.conf{,.bak}
  cat /etc/logrotate.conf
  sed -i 's/rotate [0-9]/# rotate 1/' /etc/logrotate.conf
  sed -i '1 a\rotate 26' /etc/logrotate.conf
  cat /etc/logrotate.conf
  systemctl restart rsyslog.service
}

add_kernel_parameter(){
  echo ">>>>>>>>>>>>>>>>>>>>>>>内核参数配置<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
  if ! grep -q "kernel.randomize_va_space" /etc/sysctl.conf; then
      echo "kernel.randomize_va_space = 2" | sudo tee -a /etc/sysctl.conf
  fi
  sysctl -w kernel.randomize_va_space=2 >/dev/null
}

#############应用函数###################
check_null_passwd_uid_0
# centos7 可用
centos7_add_password_policy
check_wheel
check_vsftp_service
add_sysfile_authority
ssh_config_reinforce
check_telnet_service
add_kernel_parameter
















