#!/usr/bin/env python
#If not standard should be in requirements.txt
import yaml
import sys
import tempfile
import re
import json
import getpass
import random
import atexit
import time
import requests
import os
import pyVmomi
import pyVmomi.Iso8601 as Iso8601

from pyVmomi import vim, vmodl
from pyVim.connect import Disconnect, SmartConnect
from cli.log import LoggingApp
from prettytable import PrettyTable
from threading import Thread

sys.dont_write_bytecode = True

__author__ = ['Paul.Hardy']

class VsphereTool(LoggingApp):

    def get_connection(self, config):
        try:
            connection = SmartConnect(host=config['hostname'], port=int(config['port']), user=config['username'], pwd=config['password'])
        except Exception as e:
            self.log.debug(e)
            quit("Connection: borked!")
        atexit.register(Disconnect, connection)
        return connection

    def get_config(self):
        try:
            config = yaml.load(open(self.params.config))['vsphere'][self.params.farm]
        except IOError as e:
            self.log.debug(e)
            quit("No Configuration file found at " + self.params.config)
        if config['password'] == "":
            config['password'] = str(getpass.getpass(prompt='Enter password for %s@%s: ' % (config['username'],config['hostname'])))
        return config

    def pretty_print_hosts(self,vm):
        summary = vm.summary
        annotation = summary.config.annotation
        ipAddr = summary.guest.ipAddress
        if annotation == None or annotation == "":
            annotation = "None"
        if ipAddr == None:
            if summary.config.template == True:
                ipAddr = "Template"
            else:
                ipAddr = "Not Assigned"
        question = summary.runtime.question
        if question == None:
            question == "None"
        row = [str(summary.config.name), str(summary.config.vmPathName),str(summary.config.guestFullName),annotation,str(summary.runtime.powerState),ipAddr,question]
        return row

    def pretty_print_ds(self,ds):
        space = str(ds.info.freeSpace/1024) + "/" + str(ds.info.maxFileSize/1024)
        vms = []
        for vm in ds.vm:
            vms.append(vm.name)
        vms = "\n".join(vms)
        row = [ds.name, ds.info.url, space,vms]
        return row

    def pretty_print_rp(self,rp):
        vms = []
        for vm in rp.vm:
            vms.append(vm.name)
        vms = "\n".join(vms)
        row = [rp.name, rp.overallStatus,vms]
        return row

    def pretty_print_fold(self,fold):
        children = []
        for child in fold.childEntity:
            children.append(child.name)
        row = [fold.name,fold.parent.name,fold.overallStatus,"\n".join(children)]
        return row

    def pretty_print_dc(self,dc):
        row = [dc.name,dc.parent.name,dc.overallStatus]
        return row

    def pretty_print_vlan(self,vlan):
        row = [vlan.name,str(vlan).split(':')[-1].replace('\'','')]
        return row

    def pretty_print_dvport(self,dv):
        row = [dv.name, str(dv).split(':')[-1].replace('\'','')]
        return row

    def pretty_print_hs(self,hs):
        stores = []
        for store in hs.datastore:
            stores.append(store.name)
        cpuinfo = "\n".join(["hz: " + str(hs.hardware.cpuInfo.hz), "Cores: " + str(hs.hardware.cpuInfo.numCpuCores), "Packages: " + str(hs.hardware.cpuInfo.numCpuPackages), "Threads: " + str(hs.hardware.cpuInfo.numCpuThreads)])
        meminfo = "\n".join(["Denominator: " + str(hs.hardware.memorySize.denominator), "Imag: " + str(hs.hardware.memorySize.imag), "Numerator: " + str(hs.hardware.memorySize.numerator), "Real: " + str(hs.hardware.memorySize.real)])
        sysinfo = "\n".join(["uuid: " + str(hs.hardware.systemInfo.uuid), "Model: " + str(hs.hardware.systemInfo.model), "Vendor: " + str(hs.hardware.systemInfo.vendor)])
        biosinfo = "\n".join(["Version: " + str(hs.hardware.biosInfo.biosVersion), "Release: " + str(hs.hardware.biosInfo.releaseDate)])
        row = [hs.name, hs.overallStatus,cpuinfo,meminfo,sysinfo,biosinfo,"\n".join(stores)]
        return row

    def index_instances(self, conn, subject=None, regex=None):
        row = []
        if subject == None:
            subject = self.params.detail
        template = False
        if subject == "vms":
            title = ["Name", "Path", "Guest", "Annotation", "State", "IP", "Questions"]
            recordtype = vim.VirtualMachine
        elif subject == "datastore":
            title = ["Name", "URL", "Size", "VMs"]
            recordtype = vim.Datastore
        elif subject == "resourcepools":
            title = ["Name","Status","VMs"]
            recordtype = vim.ResourcePool
        elif subject == "datacentres":
            title = ['Name', "Parent", "Status"]
            recordtype = vim.Datacenter
        elif subject == "folders":
            title = ["Name", "Parent","Status","Children"]
            recordtype = vim.Folder
        elif subject == "hostsystems":
            title = ["Name", "Status","CPU","Memory","System","BIOS","Datastores"]
            recordtype = vim.HostSystem
        elif subject == "vlans":
            title = ["Name","vSphere ID"]
            recordtype = vim.Network
        elif subject == "templates":
            title = ["Name", "Path", "Guest", "Annotation", "State", "IP", "Questions"]
            recordtype = vim.VirtualMachine
            template = True
        elif subject == "dvports":
            title = ["Name","vSphere ID"]
            recordtype = vim.dvs.DistributedVirtualPortgroup
        else:
            quit("This function has not been created yet...")
        if regex != None:
            hosts = self.get_elements_regexed(conn,recordtype,regex,template)
        else:
            hosts = self.get_elements(conn,recordtype,template)
        table = PrettyTable(title)
        for host in hosts:
            if subject == "templates" and self.params.mode == "index":
                table.add_row(self.pretty_print_hosts(host))
            elif subject == "vms" and self.params.mode == "index":
                table.add_row(self.pretty_print_hosts(host))
            elif subject == "datastore" and self.params.mode == "index":
                table.add_row(self.pretty_print_ds(host))
            elif subject == "resourcepools" and self.params.mode == "index":
                table.add_row(self.pretty_print_rp(host))
            elif subject == "folders" and self.params.mode == "index":
                table.add_row(self.pretty_print_fold(host))
            elif subject == "datacentres" and self.params.mode == "index":
                table.add_row(self.pretty_print_dc(host))
            elif subject == "vlans" and self.params.mode == "index":
                table.add_row(self.pretty_print_vlan(host))
            elif subject == "hostsystems" and self.params.mode == "index":
                table.add_row(self.pretty_print_hs(host))
            elif subject == "dvports" and self.params.mode == "index":
                table.add_row(self.pretty_print_dvport(host))
            else:
                if self.params.mode == "index":
                    self.log.error(host.summary)
        print table
        self.log.error("Number of " + subject + ": " + str(len(hosts)))
        return hosts

    def get_folder_by_path(self,conn,datacentre,path):
        folders = path.split('/')[1:]
        content = conn.RetrieveContent()
        obj = []
        dc_obj = self.get_elements_regexed(conn,vim.Datacenter,datacentre)[0]
        first_tier = content.viewManager.CreateContainerView(dc_obj, [vim.Folder], False).view
        for possible_root in first_tier:
            if possible_root.name == "vm":
                root = possible_root
                obj.append(root)
        for section in folders:
            obj.append(self.narrow_down(content,obj[-1],section))
        return obj

    def narrow_down(self,content,parent,child):
        for item in content.viewManager.CreateContainerView(parent, [vim.Folder], False).view:
            if item.name == child:
                return item

    def detokenize_scripts(self, script):
        try:
            from definitions import definitions
        except Exception as e:
            self.log.debug(e)
            self.log.error("No definitions file found! - Not detokenizing!")
            return open(script,"r")
        config = definitions(self)
        try:
            with open(script, "r") as f:
                script = f.read()
                #Create regex
                regex= re.compile('@.*@')
                while regex.search(script) != None:
                    for i, j in config.iteritems():
                        script = script.replace(i,j)
            return script
        except:
            quit('Could not find script - please check and try again')

    def create(self,conn,extra_data, creds=None):
        self.log.error("Getting " + str(extra_data['template'])  + " Template for " + str(extra_data['name']))
        templates = self.index_instances(conn, "templates", extra_data["template"])
        if len(templates) < 1:
            quit(str(extra_data['name']) + ": I could not find the template you were looking for... please check and try again!")
        elif len(templates) > 1:
            self.log.info(str(extra_data['name']) + ": Found more than one template matching " + str(extra_data['template']))
            self.log.error(str(extra_data['name']) + ": " + str(templates))
            self.log.error(str(extra_data['name']) + ": Going to use " + templates[0].config.name)
            template_vm = templates[0]
        else:
            template_vm = templates[0]
            self.log.error(str(extra_data['name']) + ": I found your template - " + str(template_vm.name))
        self.log.error(str(extra_data['name']) + " Getting Datastore")
        datastores = self.get_elements_regexed(conn,vim.ResourcePool,str(extra_data['resourcepool']))
        if len(datastores) < 1:
            quit(str(extra_data['name']) + ": I could not find the host you were looking for... please check and try again!")
        elif len(datastores) > 1:
            self.log.info(str(extra_data['name']) + ": Found more than one Datastore matching " + str(extra_data['resourcepool']))
            self.log.error(str(extra_data['name']) + ": " + str(datastores))
            self.log.error(str(extra_data['name']) + ": Going to use " + str(datastores[0].config.name))
            esx_host = datastores[0]
        else:
            self.log.error(str(extra_data['name']) + ": I Found the Datastore")
            esx_host = datastores[0]
        vm_name = str(extra_data['name'])
        mem = extra_data['memory']
        cpu = extra_data['cpu']
        vlan = extra_data['vlan']
        self.log.debug(str(vm_name) + " -  Memory: " + str(mem) + " CPU: " + str(cpu) + " VLAN: " + str(vlan) )
        devices = []
        vlan_type = vlan.split(':')[0]
        vlan = vlan.split(':')[1]
        if vlan_type == "pcnet":
            vlan_type = vim.vm.device.VirtualPCNet32()
        elif vlan_type == "e1000":
            vlan_type = vim.vm.device.VirtualE1000()
        elif vlan_type == "vmxnet2":
            vlan_type = vim.vm.device.VirtualVmxnet2()
        elif vlan_type == "vmxnet3":
            vlan_type = vim.vm.device.VirtualVmxnet3()
        else:
            self.log.error(vm_name + ": Do not what to do with nic type: " + str(vlan_type))
        nicspec = vim.vm.device.VirtualDeviceSpec()
        nicspec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        nicspec.device = vlan_type
        nicspec.device.wakeOnLanEnabled = True
        nicspec.device.addressType = 'assigned'
        nicspec.device.deviceInfo = vim.Description()
        pg_obj = self.get_elements_regexed(conn, vim.dvs.DistributedVirtualPortgroup, vlan)[0]
        dvs_port_connection = vim.dvs.PortConnection()
        dvs_port_connection.portgroupKey= pg_obj.key
        dvs_port_connection.switchUuid= pg_obj.config.distributedVirtualSwitch.uuid
        nicspec.device.backing = vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo()
        nicspec.device.backing.port = dvs_port_connection
        nicspec.device.connectable = vim.vm.device.VirtualDevice.ConnectInfo()
        nicspec.device.connectable.startConnected = True
        nicspec.device.connectable.allowGuestControl = True
        devices.append(nicspec)
        adaptermap = vim.vm.customization.AdapterMapping()
        domain = str(extra_data['domain'])
        self.log.debug(domain)
        ip = str(extra_data['ip'])
        self.log.debug(ip)
        subnet = str(extra_data['subnet'])
        self.log.debug(subnet)
        folder = str(extra_data['folder'])
        self.log.debug(folder)
        gateway = str(extra_data['gw'])
        self.log.debug(gateway)
        adaptermap.adapter = vim.vm.customization.IPSettings(ip=vim.vm.customization.FixedIp(ipAddress=ip),subnetMask=subnet, gateway=gateway, dnsDomain=domain)
        globalip = vim.vm.customization.GlobalIPSettings()
        ident = vim.vm.customization.LinuxPrep(domain=domain, hostName=vim.vm.customization.FixedName(name=vm_name))
        customspec = vim.vm.customization.Specification(nicSettingMap=[adaptermap], globalIPSettings=globalip, identity=ident)
        vmconf = vim.vm.ConfigSpec(numCPUs=cpu, memoryMB=mem, annotation=extra_data['notes'], deviceChange=devices)
        relocateSpec = vim.vm.RelocateSpec(pool=esx_host ,datastore=self.get_elements_regexed(conn, vim.Datastore ,extra_data['datastore'])[0])
        cloneSpec = vim.vm.CloneSpec(powerOn=True, template=False,customization=customspec,location=relocateSpec, config=vmconf)
        vmFolder = self.get_folder_by_path(conn,extra_data['datacentre'],extra_data['folder'])[-1]
        clone = template_vm.Clone(name=vm_name, folder=vmFolder, spec=cloneSpec)
        self.log.info(vm_name + ": Waiting for VM creation!")
        state = clone.info.state
        while state == "running":
            time.sleep(30)
            state = clone.info.state
            self.log.info(vm_name + ": " + str(state))
        try:
            vm = self.get_elements_regexed(conn,vim.VirtualMachine,vm_name)[0]
        except IndexError as e:
            self.log.debug(vm_name + ": " + str(e))
            self.log.error(vm_name + ": Could not find VM after creation - Assumed it did not create and continuing")
            return "error"
        if state == "error":
            self.log.error("Whoops! Your vSphere seems to be having a funny moment")
            try:
                self.log.error(clone.info.error.msg)
            except:
                self.log.error("No Error - Must be underlying host issues... will try again!")
                self.create(conn,extra_data, creds)
                return
            if clone.info.error.msg == "Cannot connect to host.":
                vm.Destroy()
                self.log.error("Delete the VM and try again?")
                time.sleep(10)
                self.create(conn, extra_data, creds)
                return
        try:
            if clone.info.error.msg == "The name '" + vm_name + "' already exists.":
                self.log.error("The instance already exists")
                if vm.runtime.powerState == "poweredOn":
                    self.log.info(vm_name + ": Powering on - Assumed configured and moving on to the next! - please delete instance and rerun if this is not the case!")
                    vm.PowerOnVM_Task()
                    return "exists"
        except Exception as e:
            self.log.debug(vm_name + str(e))
            self.log.info(vm_name + ": Woohoo! No Errors during the cloning phase!")
        self.log.info(vm_name + ": VM was created on the vSphere")
        time.sleep(10)
        state = vm.runtime.powerState
        self.log.info(vm_name + ": Current state of VM is - " + str(state))
        if state != "poweredOn":
            self.log.warn("There has been a problem... trying to work out what it is and get this VM up!")
            self.log.debug(vm_name + ": " + str(clone.info))
            self.log.debug(vm_name + ": Clone Error Message - " + str(clone.info.error.msg))
            result = vm.runtime.powerState
            while result != 'poweredOn':
                self.log.info("VMX Error - Not enough resources... aka Silly vSphere Syndrome!!")
                self.log.warn("Attempting Migration!")
                all_hosts = self.index_instances(conn, subject="hostsystems", regex=None)
                esx_host = random.choice(all_hosts)
                self.log.debug(vm_name + ": Migrating to - " + str(esx_host.name))
                relocate_spec = vim.vm.RelocateSpec(host=esx_host)
                reloc = vm.Relocate(relocate_spec)
                while reloc.info.state == "running":
                    self.log.info("Waiting for relocation to complete!")
                    time.sleep(10)
                self.log.debug(vm_name + ": Powering On - Host:" + str(esx_host.name))
                vm.PowerOnVM_Task()
                time.sleep(10)
                result = vm.runtime.powerState
            if vm.runtime.powerState != "poweredOn":
                vm.PowerOnVM_Task()
        result = vm.runtime.powerState
        while result != 'poweredOn':
            self.log.info(vm_name + ": Waiting for VM to power up!")
            if result == 'poweredOff':
                test = vm.PowerOnVM_Task()
            result = vm.runtime.powerState
            time.sleep(15)
        self.log.info(vm_name + ": Looks good! - Let's wait for the OS to be ready!")
        ipAddr = vm.summary.guest.ipAddress
        while ipAddr == None:
            self.log.info(vm_name + ": Waiting for OS to start up!")
            time.sleep(30)
            ipAddr = vm.summary.guest.ipAddress
        self.log.info(vm_name + ": w00t! w00t! We are now ready for configuration!")
        self.log.debug(vm_name + ": VM details are: " + str(extra_data))
        self.log.debug(vm_name + " current State is: " + str(vm.runtime.powerState))
        if extra_data['artifacts'] and extra_data['artifacts'] is not None:
            self.drop_a_file(conn,creds,regex=vm_name,artifacts=extra_data['artifacts'])
        if extra_data['scripts'] and extra_data['scripts'] is not None:
            for script in extra_data['scripts']:
                self.run_a_script(conn,creds,regex=vm_name,script=script)
        if extra_data['commands'] and extra_data['commands'] is not None:
            for command in extra_data['commands']:
                self.run_a_command(conn,creds,regex=vm_name,command=command)
        time.sleep(10)

    def verify_process(self, content, vm, creds, pid):
        pids = []
        processes = content.guestOperationsManager.processManager.ListProcessesInGuest(vm=vm, auth=creds)
        for process in processes:
            if process.pid == pid:
                if process.exitCode == None:
                    self.log.debug("still running process!")
                    reply = content.guestOperationsManager.fileManager.InitiateFileTransferFromGuest(guestFilePath="/tmp/output.txt",vm=vm,auth=creds)
                    entry = requests.get(reply.url, verify=False).text
                    print chr(27) + "[2J" #Clear Screen
                    self.log.error("running on " + vm.name)
                    self.log.error(entry)
                    exit_code = 1
                    time.sleep(10)
                else:
                    self.log.info("finished process!")
                    exit_code = 2
        return exit_code

    def exec_command(self, content, vm, creds, args, program_path):
        cmdspec = vim.vm.guest.ProcessManager.ProgramSpec(arguments=args, programPath=program_path)
        output = content.guestOperationsManager.processManager.StartProgramInGuest(vm=vm, auth=creds, spec=cmdspec)
        return output

    def snapshot(conn,regex=None):
        if regex == None:
            regex = self.params.regex
        vms = get_elements_regexed(conn, vim.VirtualMachine ,regex)
        if len(vms) == 0:
            quit("I am sorry - These are not the VMs you are looking for...")
        elif len(vms) == 1:
            self.log.error("Snapshotting - " + str(vms[0].config.name))
            try:
                vms[0].CreateSnapshot() #Needs testing!
            except Exception as e:
                self.log.error("Something went wrong...")
                quit(e)
        elif len(vms) > 1:
            if self.param.auto == True:
                self.log.error("This script is running in automatic mode - All VMs found will be snapshotted")
            for vm in vms:
                if self.param.auto == True:
                    try:
                        vm.CreateSnapshot() #Needs testing!
                    except Exception as e:
                        self.log.error("Something went wrong with " + str(vm.config.name))
                else:
                    self.log.error("Snapshotting - " + str(vm.config.name))
                    resp = raw_input("\nWould you like to continue: [y/n]")
                    if resp in ['y','ye','yes','Y','Ye','Yes','YES', 'YE']:
                        vm.CreateSnapshot() #Needs testing!
                    else:
                        self.log.error("Not creating a snapshot of - " + str(vm.config.name))
                        continue

    def get_elements(self, conn, recordType, template=False):
        content = conn.RetrieveContent()
        obj = []
        container = content.viewManager.CreateContainerView(content.rootFolder, [recordType], True)
        for c in container.view:
            if template == False:
                obj.append(c)
            else:
                if c.summary.config.template == True:
                    obj.append(c)
        return obj

    def get_elements_regexed(self, conn, recordType ,regex, template=False):
        content = conn.RetrieveContent()
        obj = []
        container = content.viewManager.CreateContainerView(content.rootFolder, [recordType], True)
        for c in container.view:
            if recordType != vim.Folder:
                if c.name == regex or regex in str(c.summary):
                    if template == False:
                        obj.append(c)
                    else:
                        if c.summary.config.template == True:
                            obj.append(c)
            else:
                 if c.name == regex or regex in str(c.overallStatus):
                    if template == False:
                        obj.append(c)
                    else:
                        if c.summary.config.template == True:
                            obj.append(c)
        return obj 

    def drop_and_run(self, content, vm, program_path, args ,creds=None):
        self.log.error("Running script on - " + str(vm.config.name))
        process = self.exec_command(content, vm, creds, args, program_path)
        exists = self.verify_process(content, vm, creds, process)
        if exists == 2:
            quit("The command did not take... try again?")
        else:
            while exists == 1:
                exists = self.verify_process(content, vm, creds, process)
        reply = content.guestOperationsManager.fileManager.InitiateFileTransferFromGuest(guestFilePath="/tmp/output.txt",vm=vm,auth=creds)
        self.log.error(requests.get(reply.url, verify=False).text)
        self.log.info("Removing output now it was been viewed...")
        self.exec_command(content, vm, creds, "/tmp/output.txt", "/bin/rm")

    def run_a_command(self,conn,creds=None,regex=None, command=None):
        if command == None:
            command = self.params.Command
        if regex == None:
            regex = self.params.regex
        hosts = self.get_elements_regexed(conn, vim.VirtualMachine,regex)
        if creds == None:
            user = raw_input("Please enter the username to make alterations to the system: ")
            passwd = getpass.getpass(prompt='Enter password for the host: ')
            creds = vim.vm.guest.NamePasswordAuthentication(username=user, password=passwd)
        content = conn.RetrieveContent()
        self.log.info("Preparing Command")
        command = command + str(" > /tmp/output.txt 2>&1")
        command = command.split(' ',1)
        program_path = command[0]
        args = command[1]
        if len(hosts) == 0:
            quit("Failed - These are not the VMs you are looking for...")
        elif len(hosts) == 1:
            vm = hosts[0]
            self.drop_and_run(content, vm, program_path, args ,creds)
        elif len(hosts) > 1:
            if self.params.auto == True:
                self.log.error("This script is running in automatic mode - All VMs found will have the command run on")
            for vm in hosts:
                if self.params.auto == True:
                    self.drop_and_run(content, vm, program_path, args ,creds)
                else:
                    self.log.error("Command running on - " + str(vm.config.name))
                    resp = raw_input("\nWould you like to continue: [y/n]")
                    if resp in ['y','ye','yes','Y','Ye','Yes','YES', 'YE']:
                        self.drop_and_run(content, vm, program_path, args ,creds)
                    else:
                        self.log.error("Not running command on - " + str(vm.config.name))
                        continue
        else:
            quit("Defensive quit! - You Should NEVER get here!")

    def drop_a_file(self,conn,creds=None,regex=None,artifacts=None):
        if artifacts == None:
            artifacts = self.params.artifact
        if regex == None:
            regex = self.params.regex
        hosts = self.get_elements_regexed(conn, vim.VirtualMachine,regex)
        if creds == None:
            user = raw_input("Please enter the username to own the dropped files: ")
            passwd = getpass.getpass(prompt='Enter password for the host: ')
            creds = vim.vm.guest.NamePasswordAuthentication(username=user, password=passwd)
        content = conn.RetrieveContent()
        if len(hosts) == 0:
            quit("I am sorry - These are not the VMs you are looking for...")
        elif len(hosts) == 1:
            for artifact in artifacts:
                vm = hosts[0]
                self.log.error("Dropping files on - " + str(vm.config.name))
                attrib = vim.vm.guest.FileManager.FileAttributes()
                theFile = artifact.split("/")[-1]
                url = "/tmp/" + theFile
                try:
                    gateway = content.guestOperationsManager.fileManager.InitiateFileTransferToGuest(overwrite=True,fileSize=os.path.getsize(artifact),fileAttributes=attrib,guestFilePath=url, vm=vm,auth=creds)
                except:
                    self.log.error("There was a problem - trying again...")
                    self.drop_a_file(creds,regex,artifacts)
                self.log.debug(gateway)
                headers =   {'Content-Type': 'application/octet-stream'}
                with open(artifact, "r") as f:
                    r = requests.put(gateway,data=f,headers=headers,verify=False)
        elif len(hosts) > 1:
            for artifact in artifacts:
                if self.params.auto == True:
                    self.log.error("This script is running in automatic mode - All VMs found will have the artifacts dropped on them")
                for vm in hosts:
                    if self.params.auto == True:
                        self.log.error("Running script on - " + str(vm.config.name))
                        attrib = vim.vm.guest.FileManager.FileAttributes()
                        theFile = artifact("/")[-1]
                    url = "/tmp/" + theFile
                    gateway = content.guestOperationsManager.fileManager.InitiateFileTransferToGuest(overwrite=True,fileSize=os.path.getsize(artifact),fileAttributes=attrib,guestFilePath=url, vm=vm,auth=creds)
                    self.log.debug(gateway)
                    headers =   {'Content-Type': 'application/octet-stream'}
                    with open(artifact, "r") as f:
                        r = requests.put(gateway,data=f,headers=headers,verify=False)
                else:
                    self.log.error("Artifacts being dropped on - " + str(vm.config.name))
                    resp = raw_input("\nWould you like to continue: [y/n]")
                    if resp in ['y','ye','yes','Y','Ye','Yes','YES', 'YE']:
                        self.log.error("Dropping artifacts on - " + str(vm.config.name))
                        attrib = vim.vm.guest.FileManager.FileAttributes()
                        theFile = theFile("/")[-1]
                        url = "/tmp/" + theFile.split("/")[-1]
                        gateway = content.guestOperationsManager.fileManager.InitiateFileTransferToGuest(overwrite=True,fileSize=os.path.getsize(theFile),fileAttributes=attrib,guestFilePath=url, vm=vm,auth=creds)
                        self.log.debug(gateway)
                        headers =   {'Content-Type': 'application/octet-stream'}
                        with open(theFile, "r") as f:
                            r = requests.put(gateway,data=f,headers=headers,verify=False)
                    else:
                        self.log.error("Not running command on - " + str(vm.config.name))
                        continue
        else:
            quit("Defensive quit! - You should NEVER get to this bit!")

    def drop_the_script(self,theFile, attrib, url, creds,content, vm, args):
        self.log.error("Running script on - " + str(vm.config.name))
        gateway = content.guestOperationsManager.fileManager.InitiateFileTransferToGuest(overwrite=True,fileSize=os.path.getsize(theFile),fileAttributes=attrib,guestFilePath=url, vm=vm,auth=creds)
        self.log.debug(gateway)
        headers =   {'Content-Type': 'application/octet-stream'}
        with open(theFile, "r") as f:
            r = requests.put(gateway,data=f,headers=headers,verify=False)
            self.exec_command(content, vm, creds, "u+x " + url, "/bin/chmod")
            process = self.exec_command(content, vm, creds, url + " " + args + " >> /tmp/output.txt 2>&1", "/bin/bash")
            exists = self.verify_process(content, vm, creds, process)
            if exists == 2:
                quit("The command did not take... try again?")
            else:
                while exists == 1:
                    exists = self.verify_process(content, vm, creds, process)
            reply = content.guestOperationsManager.fileManager.InitiateFileTransferFromGuest(guestFilePath="/tmp/output.txt",vm=vm,auth=creds)
            self.log.error(requests.get(reply.url, verify=False).text)
            self.log.info("Removing output now it was been viewed...")
            self.exec_command(content, vm, creds, "/tmp/output.txt", "/bin/rm")

    def drop_the_token_script(self,script, attrib, url, creds,content, vm, args):
        self.log.error("Running script on - " + str(vm.config.name))
        with tempfile.NamedTemporaryFile() as theFile:
            theFile.write(script)
            theFile.flush()
            gateway = content.guestOperationsManager.fileManager.InitiateFileTransferToGuest(overwrite=True,fileSize=os.path.getsize(theFile.name),fileAttributes=attrib,guestFilePath=url, vm=vm,auth=creds)
            self.log.debug(gateway)
            headers = {'Content-Type': 'application/octet-stream'}
            with open(theFile.name, "r") as f:
                r = requests.put(gateway,data=f,headers=headers,verify=False)
                self.exec_command(content, vm, creds, "u+x " + url, "/bin/chmod")
                process = self.exec_command(content, vm, creds, url + " " + args + " >> /tmp/output.txt 2>&1", "/bin/bash")
                exists = self.verify_process(content, vm, creds, process)
                if exists == 2:
                    quit("The command did not take... try again?")
                else:
                    while exists == 1:
                        exists = self.verify_process(content, vm, creds, process)
                reply = content.guestOperationsManager.fileManager.InitiateFileTransferFromGuest(guestFilePath="/tmp/output.txt",vm=vm,auth=creds)
                self.log.error(requests.get(reply.url, verify=False).text)
                self.log.info("Removing output now it was been viewed...")
                self.exec_command(content, vm, creds, "/tmp/output.txt", "/bin/rm")

    def run_a_script(self,conn,creds=None,regex=None,script=None):
        if script == None:
            script = self.params.script
        if regex == None:
            regex = self.params.regex
        hosts = self.get_elements_regexed(conn, vim.VirtualMachine,regex)
        if creds == None:
            user = raw_input("Please enter the username to make alterations to the system: ")
            passwd = getpass.getpass(prompt='Enter password for the host: ')
            creds = vim.vm.guest.NamePasswordAuthentication(username=user, password=passwd)
        content = conn.RetrieveContent()
        url = "/tmp/script.sh"
        attrib = vim.vm.guest.FileManager.FileAttributes()
        theFile,space,args = script.partition(' ')
        if len(hosts) == 0:
            quit("I am sorry - These are not the VMs you are looking for...")
        elif len(hosts) == 1:
            vm = hosts[0]
            if self.params.tokenize == True:
                script = self.detokenize_scripts(theFile)
                self.log.debug(str(vm.name) + ": " +str(script))
                self.drop_the_token_script(script, attrib, url, creds,content, vm, args)
            else:
                self.drop_the_script(theFile, attrib, url, creds,content, vm, args)
        elif len(hosts) > 1:
            if self.params.auto == True:
                self.log.error("This script is running in automatic mode - All VMs found will have the command run on")
            for vm in hosts:
                if self.params.auto == True:
                    if self.params.tokenize == True:
                        script = self.detokenize_scripts(theFile)
                        self.drop_the_token_script(script, attrib, url, creds,content, vm, args)
                    else:
                        self.drop_the_script(theFile, attrib, url, creds, content, vm, args)
                else:
                    self.log.error("Command running on - " + str(vm.config.name))
                    resp = raw_input("\nWould you like to continue: [y/n]")
                    if resp in ['y','ye','yes','Y','Ye','Yes','YES', 'YE']:
                        if self.params.tokenize == True:
                            script = self.detokenize_scripts(theFile)
                            self.drop_the_token_script(script, attrib, url, creds,content, vm, args)
                        else:
                            self.drop_the_script(theFile, attrib, url, creds,content, vm, args)
                    else:
                        self.log.error("Not running command on - " + str(vm.config.name))
                        continue
        else:
            quit("Defensive quit! - You should NEVER get to this bit!")

    def powercycle(self, conn, regex=None):
        if regex == None:
            regex = self.params.regex
        hosts = self.get_elements_regexed(conn, vim.VirtualMachine,regex)
        self.log.error("Power cycle operations")
        if len(hosts) == 0:
            quit("Could not find the VM specified please try again!")
        elif len(hosts) == 1:
            if self.params.auto != True:
                self.log.error("Found " + str(hosts[0].config.name))
                resp = raw_input("\nWould you like to PowerCycle?: [y/n]")
                if resp in ['y','ye','yes','Y','Ye','Yes','YES', 'YE']:
                    hosts[0].ResetVM_Task()
            else:
                self.log.error("Found " + str(hosts[0].config.name) + " PowerCycling!")
                hosts[0].ResetVM_Task()
        else:
            self.log.error("Found " + str(len(hosts)) + " Powercycling them all!")
            for host in hosts:
                if self.params.auto != True:
                    self.log.error("Found " + str(host.config.name))
                    resp = raw_input("\nWould you like to PowerCycle?: [y/n]")
                    if resp in ['y','ye','yes','Y','Ye','Yes','YES', 'YE']:
                        host.ResetVM_Task()
                else:
                    self.log.error("Found " + str(host.config.name) + " PowerCycling!")
                    host.ResetVM_Task()

    def todo(self,conn):
        subject = self.params.detail
        if subject == "vms":
            recordtype = vim.VirtualMachine
        elif subject == "datastore":
            recordtype = vim.Datastore
        elif subject == "resourcepools":
            recordtype = vim.ResourcePool
        elif subject == "folders":
            recordtype = vim.Folder
        elif subject == "hostsystems":
            recordtype = vim.HostSystem
        elif subject == "dvports":
            recordtype = vim.dvs.DistributedVirtualPortgroup
        else:
            quit("This function has not been created yet...")
        elements = self.get_elements(conn,recordtype)
        for ele in elements:
            print str(ele.name)
            print dir(ele)
        self.log.error("VM")
        self.log.error(elements[0].config.name)
        self.log.error(dir(elements[0]))

#===========================MAIN===========================#

    def main(self):
        self.log.debug("Starting")
        mode = self.params.mode
        self.log.debug("Mode Selected: " + mode)
        self.log.debug("Getting Config")
        config = self.get_config()
        self.log.debug("Config: " + str(config['hostname']) + " as " + str(config['username']))
        self.log.debug("Connecting to vSphere")
        if self.params.Developer == True:
            connection = "test-mode"
        else:
            connection = self.get_connection(config)
        self.log.debug("Connection Test...")
        if not connection:
            message = "No connection could be established - aborting!"
            self.log.debug(message)
            quit(message)
        self.log.debug("...Passed!")
        if mode == "index":
            if self.params.detail:
                subject = self.params.detail
                regex = self.params.regex
                self.index_instances(connection,subject,regex)
            else:
                quit("the index arguement requires the detail (-d) argument to select element to view")
        elif mode == "todo":
            self.todo(connection)
        elif mode == "powercycle":
            if self.params.regex is None:
                quit("Please include a regex (-r) to know which VM to power cycle")
            self.powercycle(connection)
        elif mode == "filedrop":
            if self.params.regex == None:
                quit("Please provide a regex (-r) to match the host to drop your files on")
            if self.params.artifact == None:
                quit("Please include which files should be dropped on the host (-a [ artifact1, artifact2, artifact3 ])")
            self.drop_a_file(Connection)
        elif mode == "command":
            if self.params.Command == None:
                quit("Please provide a command (-C) to run on the GuestOS")
            if self.params.regex == None:
                quit("Please provide a regex (-r) to match the host to run your command on")
            self.run_a_command(connection)
        elif mode == "script":
            if self.params.script == None:
                quit("Please provide a script to be copied to the host (-S)")
            if self.params.regex == None:
                quit("Please provide a regex (-r) to match the host to run your script on")
            self.run_a_script(connection)
        elif mode == "snapshot":
            if not self.params.regex:
                quit("Please express (-r) which VM you would like to be snapshotted")
            if self.params.regex and self.params.regex is not None:
                self.snapshot(connection)
            else:
                quit("snapshot arguement requires the regex (-r) argument to narrow down which VMs to snapshot")
        elif mode == "create":
            if not self.params.extra or self.params.extra is None:
                quit('Please supply a yaml runlist to create the instances with using the extra flag (-e)')
            else:
                if self.params.tokenize_config == True:
                    theYaml = yaml.load(self.detokenize_scripts(self.params.extra))
                else:
                    try:
                        theYaml = yaml.load(open(self.params.extra))
                    except:
                        quit('There was a problem loading the run list yaml data... please check and try again')

                user = raw_input("Please enter the username to make alterations to the system: ")
                passwd = getpass.getpass(prompt='Enter password for the host: ')
                creds = vim.vm.guest.NamePasswordAuthentication(username=user, password=passwd)
                threads = []
                for extra_data in theYaml:
                    if "notes" not in extra_data:
                        extra_data['notes'] = ""
                    try:
                        order = extra_data['order']
                    except KeyError:
                        self.log.info("No order found - Treating as Serial build!")
                        order = "serial"
                    if order == "serial":
                        self.log.info("Serial boot of " + extra_data['name'])
                        self.create(connection, extra_data, creds)
                        if len(t) > 0:
                            self.log.info("Waiting for previous Parallel threads to complete")
                            t.join()
                    elif order == "parallel":
                        self.log.info("Parallel boot of " + extra_data['name'])
                        t = Thread(target=self.create, args=[connection, extra_data, creds])
                        t.daemon = True
                        t.name = extra_data['name']
                        threads.append(t)
                        t.start()
                    else:
                        self.log.error("Did not recognise option " + str(order) + " - Skipping!")
                        continue
                for t in threads:
                    self.log.info("Completing background threads: " + str(t.name))
                    t.join()
        else:
            message = "Please choose a Valid Mode! - You have selected %s" % mode
            self.log.debug(message)
            quit(message)
        self.log.debug("Finished")

#===========================MAGIC==============================#

if __name__ == "__main__":
    vsphere=VsphereTool()
    vsphere.add_param("-f", "--farm", help="Which vSphere you want to connect to in your config", default=None, required=True, action="store")
    vsphere.add_param("-m", "--mode", help="What to make foreman do. Excepted Values: ['index','create','command','script','snapshot','powercycle','filedrop',todo']", default=None, required=True, action="store")
    vsphere.add_param("-d", "--detail", help="What to search for: ['datastore','vms','hostsystems','dvport','templates','resourcepool','datacentres','folders','vlans']", default=None, required=False, action="store")
    vsphere.add_param("-e", "--extra", help="Extra detail to add to a given mode", default=None, required=False, action="store")
    vsphere.add_param("-c", "--config", help="Change the Configuration file to use", default="./config/config.yaml", required=False, action="store")
    vsphere.add_param("-D", "--Developer", help="A mode for a developer to use for testing that does not form a connection... not much functionality either ;-)", default=False, required=False, action="store_true")
    vsphere.add_param("-r", "--regex", help="Changes the script behaviour to search for instances", default=None, required=False, action="store")
    vsphere.add_param("-C", "--Command", help="Which command to run with arguements separated by <SOMETHING>", default=None, required=False, action="store")
    vsphere.add_param("-S", "--script", help="Which script to be run on the GuestOS on the VM", default=None, required=False, action="store")
    vsphere.add_param("-A", "--auto", help="Changes script to not prompt for instruction and take best fit where possible!", default=False, required=False, action="store_true")
    vsphere.add_param("-a", "--artifact", help="A List of files to be dropped on the server (Does not work recursivly! You may want to tar/zip files!) e.g. -a artifact1 -a artifact2", default=None, required=False, action="append")
    vsphere.add_param("-T", "--tokenize", help="Action to decide if a script that you are running on the Virtual Instance needs to be de-tokenized - Requires a definitions.py file", default=None, required=False, action="store_true")
    vsphere.add_param("-TC", "--tokenize-config", help="Action to decide if a run list being processed should be de-tokenized - Requires a definitions.py file", default=None, required=False, action="store_true")
    vsphere.run()


