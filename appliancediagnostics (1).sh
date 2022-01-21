#!/bin/bash

##################TESTS TO RUN###########################################################
preFlightChecks=(avxSupport osTest selinuxTest cpuTest ramTest diskTest tmpdiskTest systemCheckTest curlTest ntpTest dnsTest www_accessTest session_managerTest verify_firewalld_service checkDiskTransferRate weak_cipher_test portTest)
#########################################################################################

#######REQUIRED CONFIGURATION#####################################################################
MIN_CPU=4
MIN_RAM=16 #in GB (gigabytes)
MIN_DISK_SIZE=200 #in GB (gigabytes)
DISK_LOCATIONS=("/mnt")
MIN_DISK_SIZE_TMP=15
TMP_DISK_LOCATIONS=("/tmp")
URL=(app.securiti.ai privaci-registry.s3.us-west-2.amazonaws.com packages.securiti.ai prod-us-west-2-starport-layer-bucket.s3.us-west-2.amazonaws.com)
URL_PORT=(443 443 443 443)
ports=(53 4242 7496 7373 7575 3022 3023 3024 3025 8472 2379 2380 3008 3009 3010 3011 3012 3080 4001 6443 7001 10248 10249 10250 10255 32009 61008 61009 61010 61022 61023 61024)
ports_range=(30000 32767) #first element denotes start and last element denotes end of range. Special case.
securiti_ports=(5000 9100)
loopback_address=("127.0.1.1" "127.0.0.1")
session_manager_region=(ssm.us-west-2.amazonaws.com)
session_manager_region_port=(443)
MIN_DISK_RATE=52428800
strong_cipher_list=(chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr aes192-ctr aes128-ctr)
##################################################################################################

#######LOG MESSAGES#################
SUCCESS_STATUS="(PASSED)"
FAILURE_STATUS="(FAILED)"
WARNING_STATUS="(WARNING)"
####################################

#######REPORT STATUS################
WORKING_STATUS="SUPPORTED"
NOT_WORKING_STATUS="UNSUPPORTED"
UNSUPPORTED_OS_STATUS="UNSUPPORTED OS"
INSUFFICIENT_STATUS="INSUFFICIENT"
AVAILABLE_STATUS="AVAILABLE"
NOT_AVAILABLE_STATUS="NOT AVAILABLE"
INVALID_DIR_STATUS="INVALID DIRECTORY"
INSUFFICIENT_SIZE_STATUS="INSUFFICIENT SIZE"
INVALID_FTYPE_STATUS="INVALID FTYPE"
UNCONFIGURED_STATUS="UNCONFIGURED"
UNSYNCHRONISED_STATUS="UNSYNCHRONISED"
CLOCK_INDETERMINANT_STATUS="CLOCK INDETERMINANT"
LOOPBACK_ADDRESS_SET_STATUS="LOOPBACK ADDRESS SET"
UNRESOLVED_DOMAIN_STATUS="UNRESOLVED DOMAIN"
PROXY_NOT_SET_STATUS="PROXY NOT SET"
MODULES_LOADED_STATUS="ALL MODULES LOADED"
REACHABLE_STATUS="REACHABLE"
UNREACHABLE_STATUS="UNREACHABLE"
NL=$'\n'
####################################

###OS TEST VARIABLES (OS) STARTS####
MAIN_OS_MSG="Operating System Support"
ERROR_OS_MSG_1="%s is unsupported, supported OS are Ubuntu 16.04,18.04, CentOS 7.2-7.7, CentOS 8.0-8.1, RedHat 7.4-7.8, RehHat  8.0-8.2, and Amazon 2\n"
ERROR_OS_MSG_2="unable to find the operating system\n"
###OS TEST VARIABLES (OS) ENDS######

###CURL TEST VARIABLES (curl) STARTS####
MAIN_CURL_MSG="curl command Availability"
ERROR_CURL_MSG_1="curl command is not present"
###CURL TEST VARIABLES (curl) ENDS######

###CPU TEST VARIABLES (CPU) STARTS####
MAIN_CPU_MSG="CPU Availability"
ERROR_CPU_MSG_1="Available CPU:    %s\n\rMinimum required: %s\n"
###CPU TEST VARIABLES (CPU) ENDS######

###RAM TEST VARIABLES (RAM) STARTS####
MAIN_RAM_MSG="RAM Availability"
ERROR_RAM_MSG_1="Available RAM:    %s GB\n\rMinimum required: %s GB\n"
###RAM TEST VARIABLES (RAM) ENDS######

###AVX TEST VARIABLES (AVX) STARTS####
MAIN_AVX_MSG="AVX Support"
###AVX TEST VARIABLES (AVX) ENDS######

###DISK TEST VARIABLES (DISK) STARTS####
MAIN_DISK_MSG="Space/filesystem type Compatibility at "
MAIN_DISK_MSG_1="Space Availability at"
MAIN_DISK_MSG_2="Detected xfs Filesystem. ftype Compatibility at "
ERROR_DISK_MSG_1="%s directory does not exist"
ERROR_DISK_MSG_2="Available size:   %s GB\n\rMinimum required: %s GB\n"
ERROR_DISK_MSG_3="Current xfs disk ftype is not 1\n"
###DISK TEST VARIABLES (DISK) ENDS######

###NTP TEST VARIABLES (ntp) STARTS######
MAIN_NTP_MSG="NTP Service Availability"
ERROR_NTP_MSG_1="NTP Service not configured\n"
ERROR_NTP_MSG_2="Clock Unsynchronised\n"
ERROR_NTP_MSG_3="Clock state indeterminant\n"
###NTP TEST VARIABLES (ntp) ENDS########

###DNS TEST VARIABLES (dns) STARTS######
MAIN_DNS_MSG="DNS Service Availability"
ERROR_DNS_MSG_1="Cannot resolve domain name\n"
WARNING_DNS_MSG_1="loopback address set as nameserver:"
###DNS TEST VARIABLES (dns) ENDS########

###WWW ACCESS TEST VARIABLES (www) STARTS######
MAIN_WWW_MSG="Internet Accessibility"
ERROR_WWW_MSG_1="%s unreachable\n\n"
WARNING_WWW_MSG_1="http/https proxy not configured"
###WWW ACCESS TEST VARIABLES (www) ENDS########

###SYSTEMCHECK TEST VARIABLES (sys) STARTS######
MAIN_SYSTEMCHECK_MSG="System Check Configurations"
ERROR_SYSTEMCHECK_MSG_1="%s module not loaded.\n"
ERROR_SYSTEMCHECK_MSG_2="net.bridge.bridge-nf-call-iptables set to 0.\n"
ERROR_SYSTEMCHECK_MSG_3="net.ipv4.ip_forward set to 0.\n"
###SYSTEMCHECK TEST VARIABLES (sys) ENDS########

###SESSION MANAGER TEST VARIABLES (aws) STARTS#######
MAIN_SESSION_MSG="Connectivity Test for region"
ERROR_SESSION_MSG_1="%s on port %s unreachable\n\n"
###SESSION MANAGER  TEST VARIABLES (aws) ENDS########

###FIREWALLD SERVICE VARIABLES STARTS#######
MAIN_FIREWALLD_MSG="Firewalld Service"
WARNING_FIREWALLD_MSG_1="firewalld service installed on system may hamper appliance install/upgrade\n"
###FIREWALLD SERVICE VARIABLES ENDS########

###SELINUX SERVICE VARIABLES STARTS#######
SELINUX_MSG="Selinux test"
SELINUX_WARNING_MSG="Selinux enabled. This may cause installation failure"
###SELINUX SERVICE VARIABLES ENDS########

###IPTABLES SERVICE VARIABLES STARTS#######
MAIN_IPTABLES_MSG="Iptables test"
WARNING_IPTABLES_MSG="Iptables not enabled. This may cause installation failure"
###IPTABLES SERVICE VARIABLES ENDS#######

###DISK TRANSFER RATE TEST STARTS#######
MAIN_DISK_TRANSFER_MSG="Disk Transfer Rate Test"
ERROR_DISK_TRANSFER_MSG="Disk transfer rate is below 50 MB/s, this may cause installation failure"
###DISK TRANSFER RATE TEST ENDS#######

###WEAK CIPHER TEST STARTS#######
WEAK_SSH_CIPHERS_FOUND_MSG="Weak SSH ciphers found"
NO_WEAK_SSH_CIPHERS_FOUND_MSG="No weak SSH ciphers found"
###WEAK CIPHER TEST ENDS#######

diagnostic_report=""

osTest() {
  os=`cat /etc/os-release | grep -w "ID" | cut -d "=" -f 2 | sed -e 's/^"//' -e 's/"$//'`
  version=`cat /etc/os-release | grep -w "VERSION_ID" | cut -d "=" -f 2 |sed -e 's/^"//' -e 's/"$//'`
  if [ $os == "ubuntu" ];then
    if [ $version == "16.04" ] || [ $version == "18.04" ];then
      printf "%-70s %-10s\n" "$MAIN_OS_MSG" "$SUCCESS_STATUS"
      diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_OS_MSG" "$WORKING_STATUS")
     return 0
    fi
  elif [ $os == "rhel" ];then
    if [ $version == "7.4" ] || [ $version == "7.5" ] || [ $version == "7.6" ]  || [ $version == "7.7" ] || [ $version == "7.8" ] || [ $version == "7.9" ];then
      printf "%-70s %-10s\n" "$MAIN_OS_MSG" "$SUCCESS_STATUS"
      diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_OS_MSG" "$WORKING_STATUS")
      return 0
    elif [ $version == "8" ] || [ $version == "8.1" ] || [ $version == "8.2" ] || [ $version == "8.3" ];then
      printf "%-70s %-10s\n" "$MAIN_OS_MSG" "$SUCCESS_STATUS"
      service iptables status iptables > /dev/null 2>&1
      if [ $? -eq 0 ]; then
        printf "%-70s %-10s\n" "$MAIN_IPTABLES_MSG" "$SUCCESS_STATUS"
        diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_IPTABLES_MSG" "$SUCCESS_STATUS")
      else
        printf "%-70s %-10s\n" "$MAIN_IPTABLES_MSG" "$FAILURE_STATUS"
        diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_IPTABLES_MSG" "$FAILURE_STATUS")
        printf "$WARNING_IPTABLES_MSG"
      fi
      return 0
     fi
  elif [ $os == "centos" ];then
    version=`cat /etc/centos-release | cut -d " " -f 4`
    if [ $version == "7" ] || [ $version == "7.2" ] || [ $version == "7.3" ] || [ $version == "7.4" ] || [ $version == "7.5" ] || [ $version == "7.6" ] || [ $version == "7.7" ];then
      printf "%-70s %-10s\n" "$MAIN_OS_MSG" "$SUCCESS_STATUS"
      diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_OS_MSG" "$WORKING_STATUS")
      return 0
    elif [ $version == "8" ] || [ $version == "8.1" ];then
      printf "%-70s %-10s\n" "$MAIN_OS_MSG" "$SUCCESS_STATUS"
      service iptables status iptables > /dev/null 2>&1
      if [ $? -eq 0 ]; then
        printf "%-70s %-10s\n" "$MAIN_IPTABLES_MSG" "$SUCCESS_STATUS"
        diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_IPTABLES_MSG" "$SUCCESS_STATUS")
      else
        printf "%-70s %-10s\n" "$MAIN_IPTABLES_MSG" "$FAILURE_STATUS"
        diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_IPTABLES_MSG" "$FAILURE_STATUS")
        printf "$WARNING_IPTABLES_MSG"
      fi
      return 0
    fi
  elif [ $os == "amzn" ];then
    if [ $version == "2" ];then
       printf "%-70s %-10s\n" "$MAIN_OS_MSG" "$SUCCESS_STATUS"
       diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_OS_MSG" "$WORKING_STATUS")
       return 0
    fi
  fi
  printf "%-70s %-10s\n" "$MAIN_OS_MSG" "$FAILURE_STATUS"
  diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_OS_MSG" "$UNSUPPORTED_OS_STATUS")
  printf "$ERROR_OS_MSG_1" "$os"
  return 0
}

selinuxTest() {
  os=`cat /etc/os-release | grep -w "ID" | cut -d "=" -f 2 | sed -e 's/^"//' -e 's/"$//'`
  if [ $os == "centos" ] || [ $os == "rhel" ];then
   if [ `getenforce` != "Disabled" ];then
      printf "%-70s %-10s\n" "$SELINUX_MSG" "$FAILURE_STATUS"
      diagnostic_report=$(printf "%-70s %-10s\n" "$SELINUX_MSG" "$FAILURE_STATUS")
      printf "$SELINUX_WARNING_MSG"
   else
    printf "%-70s %-10s\n" "$SELINUX_MSG" "$SUCCESS_STATUS"
    diagnostic_report=$(printf "%-70s %-10s\n" "$SELINUX_MSG" "$SUCCESS_STATUS")
   fi
  fi
}

curlTest() {
  curl=`which curl | grep -i "curl"`
  if [ ! -z "$curl" ];then
    printf "%-70s %-10s\n" "$MAIN_CURL_MSG" "$SUCCESS_STATUS"
    diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_CURL_MSG" "$AVAILABLE_STATUS")
    return 0
  fi
  printf "%-70s %-10s\n" "$MAIN_CURL_MSG" "$FAILURE_STATUS"
  diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_CURL_MSG" "$NOT_AVAILABLE_STATUS")
  printf "$ERROR_CURL_MSG_1"
  return 0
}
cpuTest() {
  cpu=$(grep -c ^processor /proc/cpuinfo)
  if [ "$cpu" -ge "$MIN_CPU" ]; then
    printf "%-70s %-10s\n" "$MAIN_CPU_MSG" "$SUCCESS_STATUS"
    diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_CPU_MSG" "$AVAILABLE_STATUS")
    return 0
  fi
  printf "%-70s %-10s\n" "$MAIN_CPU_MSG" "$FAILURE_STATUS"
  diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_CPU_MSG" "$INSUFFICIENT_STATUS")
  printf "$ERROR_CPU_MSG_1" "$cpu" "$MIN_CPU"
  return 0
}

ramTest() {
  ram=`awk '/MemTotal/ {print $2}' /proc/meminfo`
  KBTOGB=$((1000 * 1000))
  ram=$((ram / KBTOGB))
  if [ "$ram" -ge "$MIN_RAM" ]; then
    printf "%-70s %-10s\n" "$MAIN_RAM_MSG" "$SUCCESS_STATUS"
    diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_RAM_MSG" "$AVAILABLE_STATUS")
    return 0
  fi
  printf "%-70s %-10s\n" "$MAIN_RAM_MSG" "$FAILURE_STATUS"
  diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_RAM_MSG" "$INSUFFICIENT_STATUS")
  printf "$ERROR_RAM_MSG_1" "$ram" "$MIN_RAM"
  return 0
}

avxSupport() {
  AVXSUPPORT=`grep avx /proc/cpuinfo`
  if [ -z "$AVXSUPPORT" ]; then
    printf "%-70s %-10s\n" "$MAIN_AVX_MSG" "$FAILURE_STATUS"
    diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_AVX_MSG" "$NOT_WORKING_STATUS")
    return 0
  fi
  printf "%-70s %-10s\n" "$MAIN_AVX_MSG" "$SUCCESS_STATUS"
  diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_AVX_MSG" "$WORKING_STATUS")
  return 0
}

checkDiskTransferRate() {
  disk_rate_str=$(dd if=/dev/zero of=/tmp/output conv=fdatasync bs=350k count=1k 2>&1)
  disk_rate=$(echo ${disk_rate_str##*s,} | tr -dc '0-9')
  disk_rate=$((disk_rate+0))

  rm /tmp/output;

  if [[ $disk_rate_str == *"MB/s"* ]];then
    MIN_DISK_RATE=50
  fi

  if [ $disk_rate -ge $MIN_DISK_RATE ]; then
    diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_DISK_TRANSFER_MSG" "$SUCCESS_STATUS")
    printf "%-70s %-10s\n" "$MAIN_DISK_TRANSFER_MSG" "$SUCCESS_STATUS"
    return 0
  fi

  diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_DISK_TRANSFER_MSG" "$FAILURE_STATUS" "$ERROR_DISK_TRANSFER_MSG")
  printf "%-70s %-10s\n" "$MAIN_DISK_TRANSFER_MSG" "$FAILURE_STATUS" "$ERROR_DISK_TRANSFER_MSG"
  return 0
}

tmpdiskTest() {
  diagnostic_report=""
  i=1
  for disk in ${TMP_DISK_LOCATIONS[*]}
    do
      if [ $i -le ${#TMP_DISK_LOCATIONS[@]} ] && [ $i -gt 1 ];then
         diagnostic_report="${diagnostic_report}${NL}${NL}"
      fi
      let i++
      if [ ! -d $disk ];then
         printf "%-70s %-10s\n" "$MAIN_DISK_MSG_1 $disk"  "$FAILURE_STATUS"
         diagnostic_report="${diagnostic_report}$(printf "%-70s %-10s\n" "$MAIN_DISK_MSG_1 ${disk}"  "$INVALID_DIR_STATUS")"
         printf "$ERROR_DISK_MSG_1" "$disk"
         printf "\n"
         continue
      fi
      disk_size=`df -hT $disk | tail -1 | awk '{print $5}' | head -c-2`
      disk_size=${disk_size%.*}
      disk_type=`df -hT $disk | tail -1 | awk '{print $2}' | head -c-1`
      if [ "$disk_size" -lt "$MIN_DISK_SIZE_TMP" ];then
          printf "%-70s %-10s\n" "$MAIN_DISK_MSG_1 $disk" "$FAILURE_STATUS"
          diagnostic_report="${diagnostic_report}$(printf "%-70s %-10s" "$MAIN_DISK_MSG_1 ${disk}" "$INSUFFICIENT_SIZE_STATUS")"
          printf "$ERROR_DISK_MSG_2" "$disk_size" "$MIN_DISK_SIZE_TMP"
          printf "\n"
          continue
      elif [ "$disk_type" == "xfs" ];then
          ftype=`xfs_info $disk | grep ftype | head -c-1 | awk '{print $6}'`
          if [ "$ftype" != "ftype=1" ];then
              printf "%-70s %-10s\n" "$MAIN_DISK_MSG_2 $disk" "$FAILURE_STATUS"
              diagnostic_report="${diagnostic_report}$(printf "%-70s %-10s" "$MAIN_DISK_MSG_2 ${disk}" "$INVALID_FTYPE_STATUS")"
              printf "$ERROR_DISK_MSG_3" "$ftype"
              printf "\n"
              continue
          fi
      fi
      printf "%-70s %-10s\n" "$MAIN_DISK_MSG $disk" "$SUCCESS_STATUS"
      diagnostic_report="${diagnostic_report}$(printf "%-70s %-10s" "$MAIN_DISK_MSG ${disk}" "$AVAILABLE_STATUS")"
      printf "\n"
    done
  return 0
}

diskTest() {
  diagnostic_report=""
  i=1
  for disk in ${DISK_LOCATIONS[*]}
    do
      if [ $i -le ${#DISK_LOCATIONS[@]} ] && [ $i -gt 1 ];then
         diagnostic_report="${diagnostic_report}${NL}${NL}"
      fi
      let i++
      if [ ! -d $disk ];then
         printf "%-70s %-10s\n" "$MAIN_DISK_MSG_1 $disk"  "$FAILURE_STATUS"
         diagnostic_report="${diagnostic_report}$(printf "%-70s %-10s\n" "$MAIN_DISK_MSG_1 ${disk}"  "$INVALID_DIR_STATUS")"
         printf "$ERROR_DISK_MSG_1" "$disk"
         printf "\n"
         continue
      fi
      disk_size=`df -hT $disk | tail -1 | awk '{print $5}' | head -c-2`
      disk_size=${disk_size%.*}
      disk_type=`df -hT $disk | tail -1 | awk '{print $2}' | head -c-1`
      if [ "$disk_size" -lt "$MIN_DISK_SIZE" ];then
          printf "%-70s %-10s\n" "$MAIN_DISK_MSG_1 $disk" "$FAILURE_STATUS"
          diagnostic_report="${diagnostic_report}$(printf "%-70s %-10s" "$MAIN_DISK_MSG_1 ${disk}" "$INSUFFICIENT_SIZE_STATUS")"
          printf "$ERROR_DISK_MSG_2" "$disk_size" "$MIN_DISK_SIZE"
          printf "\n"
          continue
      elif [ "$disk_type" == "xfs" ];then
          ftype=`xfs_info $disk | grep ftype | head -c-1 | awk '{print $6}'`
          if [ "$ftype" != "ftype=1" ];then
              printf "%-70s %-10s\n" "$MAIN_DISK_MSG_2 $disk" "$FAILURE_STATUS"
              diagnostic_report="${diagnostic_report}$(printf "%-70s %-10s" "$MAIN_DISK_MSG_2 ${disk}" "$INVALID_FTYPE_STATUS")"
              printf "$ERROR_DISK_MSG_3" "$ftype"
              printf "\n"
              continue
          fi
      fi
      printf "%-70s %-10s\n" "$MAIN_DISK_MSG $disk" "$SUCCESS_STATUS"
      diagnostic_report="${diagnostic_report}$(printf "%-70s %-10s" "$MAIN_DISK_MSG ${disk}" "$AVAILABLE_STATUS")"
      printf "\n"
    done
  return 0
}


ntpTest() {
   if [ ! -f "/etc/ntp.conf" ];then
     printf "%-70s %-10s\n" "$MAIN_NTP_MSG" "$WARNING_STATUS"
     diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_NTP_MSG" "$NOT_AVAILABLE_STATUS")
     printf "$ERROR_NTP_MSG_1"
     return 0
   fi
   ntpstat > /dev/null 2>&1
   result=$?
   if [ "$result" -eq 1 ];then
     printf "%-70s %-10s\n" "$MAIN_NTP_MSG" "$WARNING_STATUS"
     diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_NTP_MSG" "$UNSYNCHRONISED_STATUS")
     printf "$ERROR_NTP_MSG_2"
     return 0
   elif [ "$result" -eq 2 ];then
     printf "%-70s %-10s\n" "$MAIN_NTP_MSG" "$WARNING_STATUS"
     diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_NTP_MSG" "$CLOCK_INDETERMINANT_STATUS")
     printf "$ERROR_NTP_MSG_3"
     return 0
   fi
   printf "%-70s %-10s\n" "$MAIN_NTP_MSG" "$SUCCESS_STATUS"
   diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_NTP_MSG" "$AVAILABLE_STATUS")
   return 0
}

check_loopback() {
  for addr in "${loopback_address[@]}"
   do
     is_nameserver_loopback=`cat /etc/resolv.conf | grep -w $addr`
     if [ ! -z "$is_nameserver_loopback" ]; then
        printf "%-70s %-10s\n" "$WARNING_DNS_MSG_1 $addr" "$WARNING_STATUS"
        diagnostic_report="\n${diagnostic_report}$(printf "%-70s %-10s\n\n" "$WARNING_DNS_MSG_1 $addr" "$LOOPBACK_ADDRESS_SET")"
     fi
   done
}

dnsTest() {
  dns_lookup=""
  nslookup -version > /dev/null 2>&1
  ret=`echo $?`
  if [ $ret == 0 ];then
     dns_lookup=`nslookup app.securiti.ai | tail -2 | head -1 | grep -i Address`
  else
     dns_lookup=`getent hosts app.securiti.ai`
  fi
  if [ -z "$dns_lookup" ];then
    printf "%-70s %-10s\n" "$MAIN_DNS_MSG" "$FAILURE_STATUS"
    diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_DNS_MSG" "$UNRESOLVED_DOMAIN_STATUS")
    printf "$ERROR_DNS_MSG_1"
    return 0
  fi
  printf "%-70s %-10s\n" "$MAIN_DNS_MSG" "$SUCCESS_STATUS"
  diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_DNS_MSG" "$AVAILABLE_STATUS")
  check_loopback
  return 0
}

verify_proxy() {
  http_proxy=`echo $http_proxy`
  https_proxy=`echo $https_proxy`
  HTTP_PROXY=`echo $HTTP_PROXY`
  HTTPS_PROXY=`echo $HTTPS_PROXY`
  if ( [ ! -z "$http_proxy" ] || [ ! -z "$HTTP_PROXY" ] ) && ( [ ! -z "$https_proxy" ] || [ ! -z "$HTTPS_PROXY" ] );then
    return 1
  else
    printf "%-70s %-10s\n" "$WARNING_WWW_MSG_1" "$WARNING_STATUS"
    diagnostic_report="${diagnostic_report}$(printf "%-70s %-10s" "$WARNING_WWW_MSG_1" "$PROXY_NOT_SET_STATUS")"
    return 0
  fi
}

www_accessTest() {
  i=0
  diagnostic_report=""
  for url in ${URL[*]}
    do
      system_proxy=${http_proxy}
      protocol="http"
      PROTOCOL="HTTP"
      proxy_type="5"
      if [ ${URL_PORT[$i]} -eq "443" ];then
        protocol="https"
        PROTOCOL="HTTPS"
        system_proxy=${https_proxy}
        proxy_type="connect"
      fi
      curl --version > /dev/null 2>&1
      ret=`echo $?`
      if [ $ret == 0 ];then
         curl  $protocol://$url > /dev/null 2>&1
      else
        if [ -z "$system_proxy"  ];then
          echo -e "GET $protocol://$url $PROTOCOL/1.0\n\n" | nc  $url ${URL_PORT[$i]} > /dev/null 2>&1
        else
          echo -e "GET $protocol://$url $PROTOCOL/1.0\n\n" | nc -X $proxy_type -x $system_proxy $url ${URL_PORT[$i]} > /dev/null 2>&1
        fi
      fi
      if [ $? -eq 0 ]; then
        printf "%-70s %-10s\n" "$MAIN_WWW_MSG to $url" "$SUCCESS_STATUS"
        diagnostic_report="${diagnostic_report}$(printf "%-70s %-10s" "$MAIN_WWW_MSG to $url" "$AVAILABLE_STATUS")${NL}${NL}"
        printf "\n"
        continue
      else
        printf "%-70s %-10s\n" "$MAIN_WWW_MSG to $url" "$FAILURE_STATUS"
        diagnostic_report="${diagnostic_report}$(printf "%-70s %-10s" "$MAIN_WWW_MSG to $url" "$NOT_AVAILABLE_STATUS")${NL}${NL}"
        printf "$ERROR_WWW_MSG_1" "$url"
      fi
      let "i++"
      printf "\n"
    done
  verify_proxy
  return 0
}


portTest() {
   for i in "${ports[@]}"
   do
     result=`cat /etc/services | grep -w "$i/tcp" | awk '{print $1}' | head -c-1`
     if [ ! -z "$result" ];then
        ports_used+=("$i used by $result service")
     fi
   done
   start_port=${ports_range[0]}
   end_port=${ports_range[1]}
   for ((i=$start_port;i<=$end_port;i++)); do
      result=`cat /etc/services | grep -w "$i/tcp" | awk '{print $1}' | head -c-1`
     if [ ! -z "$result" ];then
        ports_used+=("$i used by $result service")
     fi
   done

   for i in "${securiti_ports[@]}"
   do
     result=`lsof -i :$i | awk 'NR==2 {print $1}' | head -c-1`
     if [ ! -z "$result" ];then
        ports_used+=("$i used by $result service")
     fi
   done

   printf "Ports in use: \n"
   diagnostic_report=$(printf "Ports in use:")
   for i in "${ports_used[@]}"
    do
      printf "\t$i\n"
      diagnostic_report="${diagnostic_report}$(printf "\n\t$i")"
    done
}

systemCheckTest() {
  modules=(br_netfilter overlay ebtable ebtable_filter ip_tables iptable_filter iptable_nat)
  for module in ${modules[*]}
   do
    module_check=`lsmod | grep $module`
    if [ -z "$module_check" ]; then
     printf "%-70s %-10s\n" "$MAIN_SYSTEMCHECK_MSG" "$FAILURE_STATUS"
     diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_SYSTEMCHECK_MSG" "$module not loaded")
     printf "$ERROR_SYSTEMCHECK_MSG_1" "$module"
     return 0
    fi
   done
  if [ `echo /proc/sys/net/bridge/bridge-nf-call-iptables` == 0 ]; then
    printf "%-70s %-10s\n" "$MAIN_SYSTEMCHECK_MSG" "$FAILURE_STATUS"
    diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_SYSTEMCHECK_MSG" "$ERROR_SYSTEMCHECK_MSG_2")
    print "$ERROR_SYSTEMCHECK_MSG_2"
    return 0
  fi
  if [ `echo /proc/sys/net/ipv4/ip_forward` == 0 ]; then
    printf "%-70s %-10s\n" "$MAIN_SYSTEMCHECK_MSG" "$FAILURE_STATUS"
    diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_SYSTEMCHECK_MSG" "$ERROR_SYSTEMCHECK_MSG_3")
    print "$ERROR_SYSTEMCHECK_MSG_3"
    return 0
  fi
  printf "%-70s %-10s\n" "$MAIN_SYSTEMCHECK_MSG" "$SUCCESS_STATUS"
  diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_SYSTEMCHECK_MSG" "$MODULES_LOADED_STATUS")
}

session_managerTest() {
  i=0
  diagnostic_report=""
  for region in ${session_manager_region[*]}
   do
    r=$(bash -c 'exec 3<> /dev/tcp/'$region'/'${session_manager_region_port[$i]}';echo $?' 2>/dev/null)
    if [ "$r" = "0" ]; then
      printf "%-70s %-10s\n" "$MAIN_SESSION_MSG $region on port ${session_manager_region_port[$i]}" "$SUCCESS_STATUS"
      diagnostic_report="${diagnostic_report}$(printf "%-70s %-10s\n" "$MAIN_SESSION_MSG $region on port ${session_manager_region_port[$i]}" "$REACHABLE_STATUS")${NL}"
    else
      printf "%-70s %-10s\n" "$MAIN_SESSION_MSG $region on port ${session_manager_region_port[$i]}" "$FAILURE_STATUS"
      diagnostic_report="${diagnostic_report}$(printf "%-70s %-10s\n" "$MAIN_SESSION_MSG $region on port ${session_manager_region_port[$i]}" "$UNREACHABLE_STATUS")${NL}"
      printf "$ERROR_SESSION_MSG_1" "$region" "${session_manager_region_port[$i]}"
    fi
    let "i++"
    printf "\n"
  done
}

verify_firewalld_service() {
  ps cax | grep firewalld > /dev/null
  if [ $? -eq 0 ]; then
    printf "%-70s %-10s\n" "$MAIN_FIREWALLD_MSG" "$WARNING_STATUS"
    diagnostic_report=$(printf "%-70s %-10s\n" "$MAIN_FIREWALLD_MSG" "$WARNING_STATUS")
    printf "$WARNING_FIREWALLD_MSG_1"
  fi
}


weak_cipher_test() {
  available_ciphers=($(sshd -T | grep "ciphers"))
  available_ciphers=(${available_ciphers[1]})
  IFS=',' read -r -a available_ciphers <<< "$available_ciphers"
  for a in "${strong_cipher_list[@]}"
     do
        available_ciphers=(${available_ciphers[@]//*$a*})

     done
  if [[ ${available_ciphers[@]} ]]; then
     printf "%-70s %-10s\n" "$WEAK_SSH_CIPHERS_FOUND_MSG" "$WARNING_STATUS"
     diagnostic_report="${diagnostic_report}$(printf "\n\n%-70s %-10s" "$WEAK_SSH_CIPHERS_FOUND_MSG" "$WARNING_STATUS")"
     printf "%s " "${available_ciphers[@]}"
     diagnostic_report="${diagnostic_report}$(printf "\n"; printf "%s " "${available_ciphers[@]}")"

  else
     printf "%-70s %-10s\n" "$NO_WEAK_SSH_CIPHERS_FOUND_MSG" "$SUCCESS_STATUS"
     diagnostic_report="${diagnostic_report}$(printf "\n\n%-70s %-10s" "$NO_WEAK_SSH_CIPHERS_FOUND_MSG" "$SUCCESS_STATUS")"
  fi
}


app_help() {
   echo "Usage: bash appliancediagnostics.sh OPTIONS"
   echo -e "\nOPTIONS:"
   echo -e "\t--report  saves diagnostic report in a file in current directory"
   echo -e "\t--console prints diagnostic report on the console"
   echo -e "\t--help    prints the help menu"
}

if [ ! -z $1 ] && [ $1 == "--report" ];then
   printf "%-70s %-10s\n" "SYSTEM CHECK" "STATUS" > diagnostics.report
   printf "%-70s %-10s\n" "============" "======" >> diagnostics.report
   printf "%-70s %-10s\n" "SYSTEM CHECK" "STATUS" > diagnostics.log
   printf "%-70s %-10s\n" "============" "======" >> diagnostics.log
   for funcMethod in ${preFlightChecks[*]}
     do
          $funcMethod --report >> diagnostics.log
          echo "$diagnostic_report" >> diagnostics.report
          echo -e >> diagnostics.report
          echo -e >> diagnostics.log
     done


elif [ ! -z $1 ] && [ $1 == "--console" ];then
    printf "%-70s %-10s\n" "SYSTEM CHECK" "STATUS"
    printf "%-70s %-10s\n" "============" "======"
    for funcMethod in ${preFlightChecks[*]}
     do
       echo -e
          $funcMethod
     done

else
   app_help
fi
