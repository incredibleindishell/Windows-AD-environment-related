$Source = @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Runtime.InteropServices;

namespace PingCastle.Scanners
{
    public class SmbScanner
	{
        [StructLayout(LayoutKind.Explicit)]
		struct SMB_Header {
			[FieldOffset(0)]
			public UInt32 Protocol;
			[FieldOffset(4)] 
			public byte Command;
			[FieldOffset(5)] 
			public int Status;
			[FieldOffset(9)] 
			public byte  Flags;
			[FieldOffset(10)] 
			public UInt16 Flags2;
			[FieldOffset(12)] 
			public UInt16 PIDHigh;
			[FieldOffset(14)] 
			public UInt64 SecurityFeatures;
			[FieldOffset(22)] 
			public UInt16 Reserved;
			[FieldOffset(24)] 
			public UInt16 TID;
			[FieldOffset(26)] 
			public UInt16 PIDLow;
			[FieldOffset(28)] 
			public UInt16 UID;
			[FieldOffset(30)] 
			public UInt16 MID;
		};
		// https://msdn.microsoft.com/en-us/library/cc246529.aspx
		[StructLayout(LayoutKind.Explicit)]
		struct SMB2_Header {
			[FieldOffset(0)]
			public UInt32 ProtocolId;
			[FieldOffset(4)]
			public UInt16 StructureSize;
			[FieldOffset(6)]
			public UInt16 CreditCharge;
			[FieldOffset(8)]
			public UInt32 Status; // to do SMB3
			[FieldOffset(12)]
			public UInt16 Command;
			[FieldOffset(14)]
			public UInt16 CreditRequest_Response;
			[FieldOffset(16)]
			public UInt32 Flags;
			[FieldOffset(20)]
			public UInt32 NextCommand;
			[FieldOffset(24)]
			public UInt64 MessageId;
			[FieldOffset(32)]
			public UInt32 Reserved;
			[FieldOffset(36)]
			public UInt32 TreeId;
			[FieldOffset(40)]
			public UInt64 SessionId;
			[FieldOffset(48)]
			public UInt64 Signature1;
			[FieldOffset(56)]
			public UInt64 Signature2;
		}

        [StructLayout(LayoutKind.Explicit)]
		struct SMB2_NegotiateRequest
		{
			[FieldOffset(0)]
			public UInt16 StructureSize;
			[FieldOffset(2)]
			public UInt16 DialectCount;
			[FieldOffset(4)]
			public UInt16 SecurityMode;
			[FieldOffset(6)]
			public UInt16 Reserved;
			[FieldOffset(8)]
			public UInt32 Capabilities;
			[FieldOffset(12)]
			public Guid ClientGuid;
			[FieldOffset(28)]
			public UInt64 ClientStartTime;
			[FieldOffset(36)]
			public UInt16 DialectToTest;
		}

		const int SMB_COM_NEGOTIATE	= 0x72;
		const int SMB2_NEGOTIATE = 0;

		const int SMB_FLAGS_CASE_INSENSITIVE = 0x08;
		const int SMB_FLAGS_CANONICALIZED_PATHS = 0x10;

		const int SMB_FLAGS2_LONG_NAMES					= 0x0001;
		const int SMB_FLAGS2_EAS							= 0x0002;

		const int SMB_FLAGS2_SECURITY_SIGNATURE_REQUIRED	= 0x0010	;
		const int SMB_FLAGS2_IS_LONG_NAME					= 0x0040;

		const int SMB_FLAGS2_ESS							= 0x0800;

		const int SMB_FLAGS2_NT_STATUS					= 0x4000;
		const int SMB_FLAGS2_UNICODE						= 0x8000;

		const int SMB_DB_FORMAT_DIALECT = 0x02;

		static byte[] GenerateSmbHeaderFromCommand(byte command)
		{
			SMB_Header header = new SMB_Header();
			header.Protocol = 0x424D53FF;
			header.Command = command;
			header.Status = 0;
			header.Flags = SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED_PATHS;
			header.Flags2 = SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_EAS | SMB_FLAGS2_SECURITY_SIGNATURE_REQUIRED | SMB_FLAGS2_IS_LONG_NAME | SMB_FLAGS2_ESS | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE;
			header.PIDHigh = 0;
			header.SecurityFeatures = 0;
			header.Reserved = 0;
			header.TID = 0xffff;
			header.PIDLow = 0xFEFF;
			header.UID = 0;
			header.MID = 0;
			return getBytes(header);
		}

		static byte[] GenerateSmb2HeaderFromCommand(byte command)
		{
			SMB2_Header header = new SMB2_Header();
			header.ProtocolId = 0x424D53FE;
			header.Command = command;
			header.StructureSize = 64;
			header.Command = command;
			header.MessageId = 0;
			header.Reserved = 0xFEFF;
			return getBytes(header);
		}

		static byte[] getBytes(object structure)
		{
			int size = Marshal.SizeOf(structure);
			byte[] arr = new byte[size];

			IntPtr ptr = Marshal.AllocHGlobal(size);
			Marshal.StructureToPtr(structure, ptr, true);
			Marshal.Copy(ptr, arr, 0, size);
			Marshal.FreeHGlobal(ptr);
			return arr;
		}

		static byte[] getDialect(string dialect)
		{
			byte[] dialectBytes = Encoding.ASCII.GetBytes(dialect);
			byte[] output = new byte[dialectBytes.Length + 2];
			output[0] = 2;
			output[output.Length - 1] = 0;
			Array.Copy(dialectBytes, 0, output, 1, dialectBytes.Length);
			return output;
		}

		static byte[] GetNegotiateMessage(byte[] dialect)
		{
			byte[] output = new byte[dialect.Length + 3];
			output[0] = 0;
			output[1] = (byte) dialect.Length;
			output[2] = 0;
			Array.Copy(dialect, 0, output, 3, dialect.Length);
			return output;
		}

		// MS-SMB2  2.2.3 SMB2 NEGOTIATE Request
		static byte[] GetNegotiateMessageSmbv2(int DialectToTest)
		{
			SMB2_NegotiateRequest request = new SMB2_NegotiateRequest();
			request.StructureSize = 36;
			request.DialectCount = 1;
			request.SecurityMode = 1; // signing enabled
			request.ClientGuid = Guid.NewGuid();
			request.DialectToTest = (UInt16) DialectToTest;
			return getBytes(request);
		}

		static byte[] GetNegotiatePacket(byte[] header, byte[] smbPacket)
		{
			byte[] output = new byte[smbPacket.Length + header.Length + 4];
			output[0] = 0;
			output[1] = 0;
			output[2] = 0;
			output[3] = (byte)(smbPacket.Length + header.Length);
			Array.Copy(header, 0, output, 4, header.Length);
			Array.Copy(smbPacket, 0, output, 4 + header.Length, smbPacket.Length);
			return output;
		}

		public static bool DoesServerSupportDialect(string server, string dialect)
		{
			Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect);
			TcpClient client = new TcpClient();
			try
			{
				client.Connect(server, 445);
			}
			catch (Exception)
			{
				throw new Exception("port 445 is closed on " + server);
			}
			try
			{
				NetworkStream stream = client.GetStream();
				byte[] header = GenerateSmbHeaderFromCommand(SMB_COM_NEGOTIATE);
				byte[] dialectEncoding = getDialect(dialect);
				byte[] negotiatemessage = GetNegotiateMessage(dialectEncoding);
				byte[] packet = GetNegotiatePacket(header, negotiatemessage);
				stream.Write(packet, 0, packet.Length);
				stream.Flush();
				byte[] netbios = new byte[4];
				if (stream.Read(netbios, 0, netbios.Length) != netbios.Length)
                    return false;
				byte[] smbHeader = new byte[Marshal.SizeOf(typeof(SMB_Header))];
				if (stream.Read(smbHeader, 0, smbHeader.Length) != smbHeader.Length)
                    return false;
				byte[] negotiateresponse = new byte[3];
				if (stream.Read(negotiateresponse, 0, negotiateresponse.Length) != negotiateresponse.Length)
                    return false;
				if (negotiateresponse[1] == 0 && negotiateresponse[2] == 0)
				{
					Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect + " = Supported");
					return true;
				}
				Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect + " = Not supported");
				return false;
			}
			catch (Exception)
			{
				throw new ApplicationException("Smb1 is not supported on " + server);
			}
		}

		public static bool DoesServerSupportDialectWithSmbV2(string server, int dialect)
		{
			Trace.WriteLine("Checking " + server + " for SMBV2 dialect 0x" + dialect.ToString("X2"));
			TcpClient client = new TcpClient();
			try
			{
				client.Connect(server, 445);
			}
			catch (Exception)
			{
				throw new Exception("port 445 is closed on " + server);
			}
			try
			{
				NetworkStream stream = client.GetStream();
				byte[] header = GenerateSmb2HeaderFromCommand(SMB2_NEGOTIATE);
				byte[] negotiatemessage = GetNegotiateMessageSmbv2(dialect);
				byte[] packet = GetNegotiatePacket(header, negotiatemessage);
				stream.Write(packet, 0, packet.Length);
				stream.Flush();
				byte[] netbios = new byte[4];
				if( stream.Read(netbios, 0, netbios.Length) != netbios.Length)
                    return false;
				byte[] smbHeader = new byte[Marshal.SizeOf(typeof(SMB2_Header))];
				if (stream.Read(smbHeader, 0, smbHeader.Length) != smbHeader.Length)
                    return false;
				if (smbHeader[8] != 0 || smbHeader[9] != 0 || smbHeader[10] != 0 || smbHeader[11] != 0)
				{
					Trace.WriteLine("Checking " + server + " for SMBV1 dialect 0x" + dialect.ToString("X2") + " = Not supported via error code");
					return false;
				}
				byte[] negotiateresponse = new byte[6];
				if (stream.Read(negotiateresponse, 0, negotiateresponse.Length) != negotiateresponse.Length)
                    return false;
				int selectedDialect = negotiateresponse[5] * 0x100 + negotiateresponse[4];
				if (selectedDialect == dialect)
				{
					Trace.WriteLine("Checking " + server + " for SMBV1 dialect 0x" + dialect.ToString("X2") + " = Supported");
					return true;
				}
				Trace.WriteLine("Checking " + server + " for SMBV1 dialect 0x" + dialect.ToString("X2") + " = Not supported via not returned dialect");
				return false;
			}
			catch (Exception)
			{
				throw new ApplicationException("Smb2 is not supported on " + server);
			}
		}

		public static bool SupportSMB1(string server)
		{
			try
			{
				return DoesServerSupportDialect(server, "NT LM 0.12");
			}
			catch (Exception)
			{
				return false;
			}
		}

		public static bool SupportSMB2(string server)
		{
			try
			{
				return (DoesServerSupportDialectWithSmbV2(server, 0x0202) || DoesServerSupportDialectWithSmbV2(server, 0x0210));
			}
			catch (Exception)
			{
				return false;
			}
		}

		public static bool SupportSMB3(string server)
		{
			try
			{
				return (DoesServerSupportDialectWithSmbV2(server, 0x0300) || DoesServerSupportDialectWithSmbV2(server, 0x0302) || DoesServerSupportDialectWithSmbV2(server, 0x0311));
			}
			catch (Exception)
			{
				return false;
			}
		}

		public static string Name { get { return "smb"; } }
        
		public static string GetCsvHeader()
		{
			return "Computer\tSMB Port Open\tSMB1(NT LM 0.12)\tSMB2(0x0202)\tSMB2(0x0210)\tSMB3(0x0300)\tSMB3(0x0302)\tSMB3(0x0311)";
		}

		public static string GetCsvData(string computer)
		{
			bool isPortOpened = true;
			bool SMBv1 = false;
			bool SMBv2_0x0202 = false;
			bool SMBv2_0x0210 = false;
			bool SMBv2_0x0300 = false;
			bool SMBv2_0x0302 = false;
			bool SMBv2_0x0311 = false;
			try
			{
				try
				{
					SMBv1 = DoesServerSupportDialect(computer, "NT LM 0.12");
				}
				catch (ApplicationException)
				{
				}
				try
				{
					SMBv2_0x0202 = DoesServerSupportDialectWithSmbV2(computer, 0x0202);
					SMBv2_0x0210 = DoesServerSupportDialectWithSmbV2(computer, 0x0210);
					SMBv2_0x0300 = DoesServerSupportDialectWithSmbV2(computer, 0x0300);
					SMBv2_0x0302 = DoesServerSupportDialectWithSmbV2(computer, 0x0302);
					SMBv2_0x0311 = DoesServerSupportDialectWithSmbV2(computer, 0x0311);
				}
				catch (ApplicationException)
				{
				}
			}
			catch (Exception)
			{
				isPortOpened = false;
			}
			return computer + "\t" + (isPortOpened ? "Yes" : "No") + "\t" + (SMBv1 ? "Yes" : "No")
															+ "\t" + (SMBv2_0x0202 ? "Yes" : "No")
															+ "\t" + (SMBv2_0x0210 ? "Yes" : "No")
															+ "\t" + (SMBv2_0x0300 ? "Yes" : "No")
															+ "\t" + (SMBv2_0x0302 ? "Yes" : "No")
															+ "\t" + (SMBv2_0x0311 ? "Yes" : "No");
		}
		
        public static void GetCsv(string computer)
        {
            Console.WriteLine(GetCsvHeader());
            Console.WriteLine(GetCsvData(computer));
        }
	}
}
"@
Add-Type -TypeDefinition $Source

# Run example:
# [PingCastle.Scanners.SmbScanner]::GetCsv("192.168.0.25")
