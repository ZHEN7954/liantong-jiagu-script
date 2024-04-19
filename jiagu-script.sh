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
  echo ">>>>>>>>>>>>>>>>><<<<<>centos7添加密码策略<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
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
  echo ">>>>>>>>>>>>>>>>><<<<<>>>>>检查wheel有无app_999<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
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




#############应用函数###################
check_null_passwd_uid_0
# centos7 可用
centos7_add_password_policy
check_wheel




















