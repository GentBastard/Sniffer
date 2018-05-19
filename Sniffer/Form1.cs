using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using SharpPcap;
using PacketDotNet;
using System.Threading;
using System.IO;

namespace SniffApp
{
    public partial class Form1 : Form
    {
        private ICaptureDevice device;
        private CaptureDeviceList devices;
        private string[] devicesNames;
        private string path;
        List<string> dataBuffer;
        int capturedPackets = 0;
        int processedPackets = 0;
        bool CaptureLaunched = false;

        public Form1()
        {
            InitializeComponent();
            button1.Text = "START";
            comboBox1.SelectedIndexChanged += comboBox1_SelectedIndexChanged;
            dataGridView1.SelectionChanged += dataGridView1_SelectionChanged;
            this.FormClosing += Form1_FormClosing;
            timer1.Interval = 100;
            timer1.Tick += new EventHandler(timer1_Tick);
            timer1.Start();
        }


        private void timer1_Tick(object sender, EventArgs e)
        {
            if (dataBuffer.Count != 0)
            {
                BinaryWriting();
            }
        }
        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            try
            {
                Action action = () =>
                {
                    path = comboBox1.Text;
                };
                Invoke(action);
            }
            catch { }
            device = devices[comboBox1.SelectedIndex];
            while (dataGridView1.Rows.Count != 0)
            {
                dataGridView1.Rows.Remove(dataGridView1.Rows[0]);
            }
            toolStripStatusLabel1.Text = "Packets: capture is not started";
            toolStripStatusLabel2.Text = "";
            device.Open(DeviceMode.Promiscuous, 3000);
            string info;
            info = device.ToString().Substring(11);
            info = info.Substring(0, info.Length - 2);
            label1.Text = info;
            label2.Text = "";
            panel1.Focus();
        }

        private void dataGridView1_SelectionChanged(object sender, EventArgs e)
        {
            if (CaptureLaunched == false)
                BinaryReading();
            else
                label2.Text = "To view information about the package, stop capture...";
        }

        public void Form1_FormClosing(object sender, EventArgs e)
        {
            //for (int i = 0; i < devicesNames.Length; i++ )
            //    File.Delete(devicesNames[i] + ".dat");
        }


        public void Start()
        {
            dataBuffer = new List<string>();
            devices = CaptureDeviceList.Instance;
            if (devices.Count < 1)
            {
                comboBox1.Enabled = false;
                button1.Enabled = false;
            }
            else
            {
                devicesNames = new string[devices.Count];
                int i = 0;
                foreach (ICaptureDevice dev in devices)
                {
                    string str = dev.ToString().Substring(dev.ToString().IndexOf("FriendlyName"));
                    if (str.Contains("Gateway"))
                    {
                        str = str.Substring(0, str.IndexOf("Gateway") - 1);
                        str = str.Substring(str.IndexOf(' ') + 1);
                    }
                    else
                    {
                        str = str.Substring(str.IndexOf(' ') + 1);
                        str = str.Substring(0, str.IndexOf("Description") - 1);
                    }
                    comboBox1.Items.Add(str);
                    File.Create(str + ".dat");
                    devicesNames[i] = str;
                    i++;
                }
                comboBox1.SelectedItem = comboBox1.Items[0];
                label2.Text = "";
                panel1.Focus();
            }
        }

        public void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            // парсинг всего пакета
            Packet packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);

            var ethernetPacket = (EthernetPacket)packet.Extract(typeof(EthernetPacket));
            var ipPacket = (IpPacket)packet.Extract(typeof(IpPacket));

            var arpPacket = (ARPPacket)packet.Extract(typeof(ARPPacket));
            var igmpPacket = (IGMPv2Packet)packet.Extract(typeof(IGMPv2Packet));
            var icmpv4Packet = (ICMPv4Packet)packet.Extract(typeof(ICMPv4Packet));
            var icmpv6Packet = (ICMPv6Packet)packet.Extract(typeof(ICMPv6Packet));
            var ospfPacket = (OSPFPacket)packet.Extract(typeof(OSPFPacket));                 
            var udpPacket = (UdpPacket)packet.Extract(typeof(UdpPacket));
            var tcpPacket = (TcpPacket)packet.Extract(typeof(TcpPacket));


            

            string srcIp = "", dstIp = "", srcPort = "", dstPort = "";
            DateTime time = e.Packet.Timeval.Date;
            int len = e.Packet.Data.Length;

            if (ipPacket != null)
            {
                
                srcIp = ipPacket.SourceAddress.ToString();
                dstIp = ipPacket.DestinationAddress.ToString();
                if (tcpPacket != null)
                {
                    srcPort = tcpPacket.SourcePort.ToString();
                    dstPort = tcpPacket.DestinationPort.ToString();
                    string prot = ipPacket.Protocol.ToString();
                    //string pack = ipPacket.Header.ToString();
                    //var hex = BitConverter.ToString(ipPacket.Header);
                    //hex = hex.Replace("-", "");
                    //byte[] raw = new byte[hex.Length / 2];
                    //for (int i = 0; i < raw.Length; i++)
                    //{
                    //    raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
                    //}
                    //string pack = Encoding.ASCII.GetString(raw);
                    capturedPackets++;
                    dataBuffer.Add(tcpPacket.PrintHex());
                    try
                    {
                        Action action = () =>
                        {
                            dataGridView1.Rows.Add(dataGridView1.Rows.Count + 1, srcIp, srcPort, dstIp, dstPort, len, GetProtocol(Convert.ToInt32(srcPort), Convert.ToInt32(dstPort), prot));
                            dataGridView1.Rows[dataGridView1.Rows.Count - 1].DefaultCellStyle.BackColor = Color.PaleGreen;
                            dataGridView1.FirstDisplayedScrollingRowIndex = dataGridView1.Rows.Count - 1;
                            toolStripStatusLabel1.Text = "Packets captured: " + capturedPackets;

                        };
                        Invoke(action);
                    }
                    catch { }
                }

                if (udpPacket != null)
                {
                    srcPort = udpPacket.SourcePort.ToString();
                    dstPort = udpPacket.DestinationPort.ToString();
                    string protocol = ipPacket.Protocol.ToString();
                    capturedPackets++;
                    dataBuffer.Add(udpPacket.PrintHex());
                    try
                    {
                        Action action = () =>
                        {
                            dataGridView1.Rows.Add(dataGridView1.Rows.Count + 1, srcIp, srcPort, dstIp, dstPort, len, GetProtocol(Convert.ToInt32(srcPort), Convert.ToInt32(dstPort), protocol));
                            dataGridView1.Rows[dataGridView1.Rows.Count - 1].DefaultCellStyle.BackColor = Color.LightSkyBlue;
                            dataGridView1.FirstDisplayedScrollingRowIndex = dataGridView1.Rows.Count - 1;
                            toolStripStatusLabel1.Text = "Packets captured: " + capturedPackets;
                        };
                        Invoke(action);
                    }
                    catch { }
                }

                if (igmpPacket != null)
                {
                    capturedPackets++;
                    dataBuffer.Add(ipPacket.PrintHex());
                    try
                    {
                        Action action = () =>
                        {
                            dataGridView1.Rows.Add(dataGridView1.Rows.Count + 1, srcIp, "", dstIp, "", len, "IGMP");
                            dataGridView1.Rows[dataGridView1.Rows.Count - 1].DefaultCellStyle.BackColor = Color.PapayaWhip;
                            dataGridView1.FirstDisplayedScrollingRowIndex = dataGridView1.Rows.Count - 1;
                            toolStripStatusLabel1.Text = "Packets captured: " + capturedPackets;
                        };
                        Invoke(action);
                    }
                    catch { }
                }

                if (arpPacket != null)
                {
                    srcIp = arpPacket.SenderProtocolAddress.ToString();
                    dstIp = arpPacket.TargetProtocolAddress.ToString();
                    capturedPackets++;
                    dataBuffer.Add(ipPacket.PrintHex());
                    try
                    {
                        Action action = () =>
                        {
                            dataGridView1.Rows.Add(dataGridView1.Rows.Count + 1, srcIp, "", dstIp, "", len, "ARP");
                            dataGridView1.Rows[dataGridView1.Rows.Count - 1].DefaultCellStyle.BackColor = Color.PowderBlue;
                            dataGridView1.FirstDisplayedScrollingRowIndex = dataGridView1.Rows.Count - 1;
                            toolStripStatusLabel1.Text = "Packets captured: " + capturedPackets;
                        };
                        Invoke(action);
                    }
                    catch { }
                }

                if (icmpv4Packet != null)
                {
                    capturedPackets++;
                    dataBuffer.Add(icmpv4Packet.PrintHex());
                    try
                    {
                        Action action = () =>
                        {
                            dataGridView1.Rows.Add(dataGridView1.Rows.Count + 1, srcIp, "", dstIp, "", len, "ICMPV4");
                            dataGridView1.Rows[dataGridView1.Rows.Count - 1].DefaultCellStyle.BackColor = Color.MediumSlateBlue;
                            dataGridView1.FirstDisplayedScrollingRowIndex = dataGridView1.Rows.Count - 1;
                            toolStripStatusLabel1.Text = "Packets captured: " + capturedPackets;
                        };
                        Invoke(action);
                    }
                    catch { }
                }

                if (icmpv6Packet != null)
                {
                    capturedPackets++;
                    dataBuffer.Add(icmpv6Packet.PrintHex());
                    try
                    {
                        Action action = () =>
                        {
                            dataGridView1.Rows.Add(dataGridView1.Rows.Count + 1, srcIp, "", dstIp, "", len, "ICMPV6");
                            dataGridView1.Rows[dataGridView1.Rows.Count - 1].DefaultCellStyle.BackColor = Color.MediumPurple;
                            dataGridView1.FirstDisplayedScrollingRowIndex = dataGridView1.Rows.Count - 1;
                            toolStripStatusLabel1.Text = "Packets captured: " + capturedPackets;
                        };
                        Invoke(action);
                    }
                    catch { }
                }

                if (ospfPacket != null)
                {                    
                    capturedPackets++;
                    dataBuffer.Add(ospfPacket.PrintHex());
                    try
                    {
                        Action action = () =>
                        {
                            dataGridView1.Rows.Add(dataGridView1.Rows.Count + 1, srcIp, "", dstIp, "", len, "OSPF");
                            dataGridView1.Rows[dataGridView1.Rows.Count - 1].DefaultCellStyle.BackColor = Color.AntiqueWhite;
                            dataGridView1.FirstDisplayedScrollingRowIndex = dataGridView1.Rows.Count - 1;
                            toolStripStatusLabel1.Text = "Packets captured: " + capturedPackets;
                        };
                        Invoke(action);
                    }
                    catch { }
                }
            }

        }


        public void BinaryWriting()
        {
            try
            {
                BinaryWriter writer = new BinaryWriter(File.Open(path + ".dat", FileMode.Append));
                writer.Write(dataBuffer[0]);
                writer.Close();
                dataBuffer.Remove(dataBuffer[0]);
                processedPackets++;
                toolStripStatusLabel2.Text = "Packets processed: " + processedPackets;
            }
            catch { }
        }

        public void BinaryReading()
        {
            label2.Text = "Please wait...";
            BinaryReader reader = new BinaryReader(File.Open(path + ".dat", FileMode.Open), Encoding.ASCII);
            //bool IsFounded = false;
            int i = 1;
            //while (true)
            //{
            while (reader.PeekChar() > -1)
            {
                string data = reader.ReadString();
                if (i.ToString() == dataGridView1.SelectedRows[0].Cells[0].Value.ToString())
                {
                    label2.Text = data;
                    //IsFounded = true;
                    break;
                }
                i++;
            }
            //    if (IsFounded == true)
            //        break;
            //}
            reader.Close();
        }


        public string GetProtocol(int srcPort, int dstPort, string Default)
        {
            switch (srcPort)
            {
                case 20:
                    return "FTP-DATA";
                case 21:
                    return "FTP";
                case 22:
                    return "SSH";
                case 23:
                    return "Telnet";
                case 25:
                    return "SMTP";
                case 53:
                    return "DNS";
                case 67:
                    return "DHCP";
                case 68:
                    return "DHCP";
                case 80:
                    return "HTTP";
                case 110:
                    return "POP3";
                case 143:
                    return "IMAP";
                case 194:
                    return "IRC";
                case 443:
                    return "HTTPS";
                case 546:
                    return "DHCPV6-CLIENT";
                case 547:
                    return "DHCPV6-SERVER";
                case 993:
                    return "IMAPS";
                default:
                    switch (dstPort)
                    {
                        case 20:
                            return "FTP-DATA";
                        case 21:
                            return "FTP";
                        case 22:
                            return "SSH";
                        case 23:
                            return "Telnet";
                        case 25:
                            return "SMTP";
                        case 53:
                            return "DNS";
                        case 67:
                            return "DHCP";
                        case 68:
                            return "DHCP";
                        case 80:
                            return "HTTP";
                        case 110:
                            return "POP3";
                        case 143:
                            return "IMAP";
                        case 194:
                            return "IRC";
                        case 443:
                            return "HTTPS";
                        case 546:
                            return "DHCPV6-CLIENT";
                        case 547:
                            return "DHCPV6-SERVER";
                        case 993:
                            return "IMAPS";
                        default:
                            return Default;
                    }
            }

        }

        private void Form1_Load(object sender, EventArgs e)
        {
            Start();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (CaptureLaunched == true)
            {
                button1.Text = "Stopping...";
                try
                {
                    device.StopCapture();
                }
                catch { }
                device.Close();
                button1.Text = "START";
                CaptureLaunched = false;
                comboBox1.Enabled = true;
            }
            else if (CaptureLaunched == false)
            {
                button1.Text = "Starting...";
                device.OnPacketArrival += new SharpPcap.PacketArrivalEventHandler(device_OnPacketArrival);
                int readTimeoutMilliseconds = 1000;
                device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
                device.StartCapture();
                button1.Text = "STOP";
                CaptureLaunched = true;
                comboBox1.Enabled = false;
            }
        }

    }
}

