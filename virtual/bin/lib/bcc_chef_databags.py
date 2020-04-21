# Copyright 2020, Bloomberg Finance L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
from Crypto.PublicKey import RSA
from OpenSSL import crypto, SSL
import os
import secrets
import string
import struct
import subprocess
import time
import uuid
import yaml

class SSL:

    def __init__(self):

        # create a key pair
        self.__key = crypto.PKey()
        self.__key.generate_key(crypto.TYPE_RSA, 4096)

        # create a self-signed cert
        self.__cert = crypto.X509()
        self.__cert.get_subject().C = "US"
        self.__cert.get_subject().ST = "New York"
        self.__cert.get_subject().L = "New York City"
        self.__cert.get_subject().O = "Bloomberg L.P."
        self.__cert.get_subject().OU = "openstack"
        self.__cert.get_subject().CN = "bcpc.example.com"
        self.__cert.get_subject().emailAddress = "null@example.com"
        self.__cert.set_serial_number(0)
        self.__cert.gmtime_adj_notBefore(0)
        self.__cert.gmtime_adj_notAfter(16*365*24*60*60)
        self.__cert.set_issuer(self.__cert.get_subject())
        self.__cert.set_pubkey(self.__key)
        self.__cert.sign(self.__key, 'sha512')

    def crt(self):
        certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, self.__cert)
        return base64.b64encode(certificate).decode()

    def key(self):
        private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, self.__key)
        return base64.b64encode(private_key).decode()

class EtcdSSL:
    def ca_crt(self):
        return 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUQ2RENDQXRDZ0F3SUJBZ0lVVWl4bHNhYkdFMVFTOTE5OFdUZ3gyL0xXaHRFd0RRWUpLb1pJaHZjTkFRRUwKQlFBd2VqRUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdUQ0U1bGR5QlpiM0pyTVJFd0R3WURWUVFIRXdoTwpaWGNnV1c5eWF6RVZNQk1HQTFVRUNoTU1RbXh2YjIxaVpYSm5JRXhRTVNFd0h3WURWUVFMRXhoRlRrY2dRMnh2CmRXUWdTVzVtY21GemRISjFZM1IxY21VeEN6QUpCZ05WQkFNVEFtTmhNQjRYRFRFNU1EY3dOekU0TVRnd01Gb1gKRFRJME1EY3dOVEU0TVRnd01Gb3dlakVMTUFrR0ExVUVCaE1DVlZNeEVUQVBCZ05WQkFnVENFNWxkeUJaYjNKcgpNUkV3RHdZRFZRUUhFd2hPWlhjZ1dXOXlhekVWTUJNR0ExVUVDaE1NUW14dmIyMWlaWEpuSUV4UU1TRXdId1lEClZRUUxFeGhGVGtjZ1EyeHZkV1FnU1c1bWNtRnpkSEoxWTNSMWNtVXhDekFKQmdOVkJBTVRBbU5oTUlJQklqQU4KQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBbm5VbW56NVRpV0g4VlNIY3gybjBKeHoydjR3bQo2UkYwbmdHK05JRGl5Y1ZOVUdXaHZxYWV3THhYcVBsbVI2L1JzZW5tVmpVa2lRdjBmZkxubDUxU01sdFhaTnkwCjYrMmhHbU1SMXoxWm9FcU1DaFEwY05uVFY4dktjNzYxdEtlUzRyWE9ZSnR5WDlIa0tPSm8xazFRMHludzBTVHUKbzFVQmVNUlM3QkFWZWlBUzhBcWlCKzlwSDlhT2FvbXVoUWJrWGNJQmN3blNlbFU1a2pCWWtXL2M5UVFndEFkRApXek5QUFVmWjBqVklCK2JFYWFmZE4zRHhWYmROSU8rcjFWTGZPaE14eVNHclFDSjEzNlNhSitGUUdDQWNUUElTCnFVem9mVWpkRi9CcGk5VlVBdTYvLyt5S1dqZmg3bkZ1ZDUvWXBRdlA1ZGRYUnNWaWxTdTgyQythWVFJREFRQUIKbzJZd1pEQU9CZ05WSFE4QkFmOEVCQU1DQVFZd0VnWURWUjBUQVFIL0JBZ3dCZ0VCL3dJQkFqQWRCZ05WSFE0RQpGZ1FVdG9zTnB0Vk5IRmg4NzhRdXZkYStqYTVnRDFVd0h3WURWUjBqQkJnd0ZvQVV0b3NOcHRWTkhGaDg3OFF1CnZkYStqYTVnRDFVd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFBczJyRjdodmRqK0Q1S2dNdDVOZ1RremxRSngKeS9yK0VNRHdhUWlrV2p4OXNiWktEcTZwb1FER1BSUVRNbi9oRWMzM0M1T2ZqcEdVMllvZ01wQjdjd0wrTzh2SQpmTEk4ZEhrVFZGQ0IxcWkrdlJJVkRqZjZKSHNSMlplVHE1WGFxYWRIcnJEczJKL0tIRGFiZkFRT2YySWFNRzlZCkRwcWtyZXFTOGtBTmZNTzkvOGE5UTV0OU11YnBtRmZoUEdjSGZjYTU0UEJIemhuZko3cHRTODNwWENYdWxxY3AKMEFNdWVMYlQxUG5kcHVQVVlLQW5CMjdHSExNMW4zTFZjL09vZ1RDL1NZN3YyQzVJZVFKZnZLa3cvWmJyQkNMRgpoZG1yUVNNdUxWaU9iUUpoZmVzUnlkTEpGMjh2dXJMa3pDNjkwdWx4TWV3NHhYNU9IdktHMGlxdmM5az0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
    def server_crt(self):
        return 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVLakNDQXhLZ0F3SUJBZ0lVQjBaZWNyUzl5SFcvYWJvdlBUWEFRWkhDSitnd0RRWUpLb1pJaHZjTkFRRUwKQlFBd2VqRUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdUQ0U1bGR5QlpiM0pyTVJFd0R3WURWUVFIRXdoTwpaWGNnV1c5eWF6RVZNQk1HQTFVRUNoTU1RbXh2YjIxaVpYSm5JRXhRTVNFd0h3WURWUVFMRXhoRlRrY2dRMnh2CmRXUWdTVzVtY21GemRISjFZM1IxY21VeEN6QUpCZ05WQkFNVEFtTmhNQjRYRFRFNU1EY3dOekU0TVRnd01Gb1gKRFRNMU1EY3dNekU0TVRnd01Gb3dmakVMTUFrR0ExVUVCaE1DVlZNeEVUQVBCZ05WQkFnVENFNWxkeUJaYjNKcgpNUkV3RHdZRFZRUUhFd2hPWlhjZ1dXOXlhekVWTUJNR0ExVUVDaE1NUW14dmIyMWlaWEpuSUV4UU1TRXdId1lEClZRUUxFeGhGVGtjZ1EyeHZkV1FnU1c1bWNtRnpkSEoxWTNSMWNtVXhEekFOQmdOVkJBTVRCbk5sY25abGNqQ0MKQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFMRXNiSHFrNzBiRnFOWVdIWXZ1LzBTQwpFL1hTNnJPL3RRdkM3YlRkNVhXQUlkVzhNd0NpUEZsMkxLUzhDaEpKeGhaZm4rNUx2eHlVMEd5L3BMMjdJeWo3Cnh1RDE4b1lXK1F6VEt4ZUhjL1BzS3E5anFpMEY5ZWtXYVBTSm50VHQ3S0kxUlU0ZHhhSUNMSHB2Tm9ZZURqcHQKc1ZJK1liVXpsdXpZT1JKcGpGSDUybWZYalBxMFlhZWFwdkZPdFNhZGJ1dHVEV0RKRmtjKzEwdkcxZncwRFhJegpvanJZaHhYQUZPOXYyN2JoaDJsWjIyUnZ2UDJGTThPajd6YWlLbXZxOXNrRFNDVGdtR1dGUkFSYlZRcUUvcGRvCm1HSG5abDdhTjFYTnUrRlRzcGtoZDQxT1dEUnVPS1N2V1ZzNU5zQnU3RnNMVlR5RlgwcVhTRjdtblN6VHQ0OEMKQXdFQUFhT0JvekNCb0RBT0JnTlZIUThCQWY4RUJBTUNCYUF3SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdFRwpDQ3NHQVFVRkJ3TUNNQXdHQTFVZEV3RUIvd1FDTUFBd0hRWURWUjBPQkJZRUZNS05GMGkxQ1BYWkVqUFE2ZytmCkl1S0dxM3VkTUI4R0ExVWRJd1FZTUJhQUZMYUxEYWJWVFJ4WWZPL0VMcjNXdm8ydVlBOVZNQ0VHQTFVZEVRUWEKTUJpSEJBcEJBQUtIQkFwQkFCQ0hCQXBCQUNDSEJIOEFBQUV3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUhTRwpRcXgvU3pZN3BibEoyQndHMjNaVjFwd3UvZmpwQndnU1FIcXhRRlBEQlhRVEpIQTNocmVqZU9sTDlSRGV3L2djCkJHam5uVjdwakRlVWdvRFBSb0pYaHh0UEQxUmNPc3ZLdnFtd3BSZzB2YmIxTkdtYzVKQ29XbnZ1dWdiUXk1RTkKT28rUDUwckV5eW5xTmNPc0tIZDZ1cUxRNGcrTmpkc08zdjMza2ZPODFJMmc0bG1Zc0RmL2xnOTF1Smd6TkY1cApGcnJzdXAvQXNmaWlwS0VhczFFOTlmTzhKWEFZalJSSU9QSC80UkNRQjRYVHdoUndEUEoyWVEzQkx1TTJoSHVkCmhJREVPa0JuS083N0xRaWJiUjlvSnEvYy9EdnJPVlBkMm43THFGbTRmSHpDby9CMkpybGx0VmlDK2hTL214aUsKTUwyRTRxZDd6OXZELzBhbDl4Zz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
    def server_key(self):
        return 'LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb2dJQkFBS0NBUUVBc1N4c2VxVHZSc1dvMWhZZGkrNy9SSUlUOWRMcXM3KzFDOEx0dE4zbGRZQWgxYnd6CkFLSThXWFlzcEx3S0VrbkdGbCtmN2t1L0hKVFFiTCtrdmJzaktQdkc0UFh5aGhiNUROTXJGNGR6OCt3cXIyT3EKTFFYMTZSWm85SW1lMU8zc29qVkZUaDNGb2dJc2VtODJoaDRPT20yeFVqNWh0VE9XN05nNUVtbU1VZm5hWjllTQorclJocDVxbThVNjFKcDF1NjI0TllNa1dSejdYUzhiVi9EUU5jak9pT3RpSEZjQVU3Mi9idHVHSGFWbmJaRys4Ci9ZVXp3NlB2TnFJcWErcjJ5UU5JSk9DWVpZVkVCRnRWQ29UK2wyaVlZZWRtWHRvM1ZjMjc0Vk95bVNGM2pVNVkKTkc0NHBLOVpXemsyd0c3c1d3dFZQSVZmU3BkSVh1YWRMTk8zandJREFRQUJBb0lCQUVBZW1hdlJJUjkxeldLZApZbGdRU0tYY2hhakRpbGsvR2lDRmpVMlZ1TU5MZWZOR1J4Y0ZuOTJvblFPSllnTzRXMDRoa1ZuR1pBWE4vWmc5Cnl6czNETVI2U2tHRUFSOXlGUFFGUUdVbGlsdE9yeXdHWDhJbmxCV2xISnJUYTM0WUZUbW5HY3Zwam1yUmFwTnMKeUVqRmU5UzllaDBQb29EWGlObHliMFV3bWEzWXFrUFJvTHJWR0JhK2dFbTNmaDNWRzVOUlNtRDM2ZytGenRyYQpPTWh3ZXhoS3IzcmhpOXhGMXZ5UzEzQmRkTGwrUGhPWXhna2hzdWQzVU01V1RZRlRuRVQySFJRR25PeVBIbjRJCnZibHlHTC9rZjVWT0hmallTcnJyeGkwNzQzZ09BUzQ2eVdDQU9KbmM1NGlwL2YwTjdPeFRGMEJuSUtyODlrL3kKclZ6Sit4RUNnWUVBeVdQbDVwTXp5VUhZYXNBM0JOdCtGQkovWlc4UWpxTUl5eFVkbjZLYVczY2pCWCtNVXNvTApzZHJnVWl1U1A3TVN0SmVTeDF6cUx6Yzg0cVQxQ2kxQWxzSHpGSVR1djV6c1ovSmY3Vjg0ZkdJemhqUDNNUW9qCnU2YnViV2Voc2UrNzVFNzNsbHJLMkdnMUR2cHhnZXYraFVpSFhZY010RGN0cW5EUVpJU08wRnNDZ1lFQTRUZHoKbm9xclh1bkJ1anhkQVpqb28yV0tYYjg1eUJXc2VFVlVHVWxyQjNwNVB5Mm5oK0hvK3h6cXJXaWhuMmpnei9VaQpuK2dQc2V3bzlrWUFmeCtpREFGQWsrRXZGQzJsTWpDWnhRZmpLWHhIbnJEejgxOVBKcDRIYk1YSjZkTERXM1hSCldwdDQxbklWWUw4dllhL2txNXU0NGNLb0syNUdzbHp5WlBXazI5MENnWUFaL2FTTUQyOWRoL3Z3T3dKZXhCMFAKWmh1KzhZaUhnQThBZHFjdUZRUXF6Y05kVUVyQjNJV0ozSithdXpqU3M3KzBRdU9VaXk5R0RMRDA1eWtndVJwZQoyb1VPbnVGWkpWMTFSTmlRZi91QVFnUTRTN2laUVorKzlocExVRmFUNmthcmZtMkJvQklSdjlFcEw3VTZlVVNOCjJ3QnRWNktTRjVUekxFQVkyT3E5aFFLQmdHYWRBVXpuR1pXeEk5ZGEwWFY4MmVJNHpZWlJMbDUvb1lsYTdTcG8KVFIrbktiOGphZ1Y3Wk0rbEtUZkJTSUo5SXBFZHU1em4rdDZ5SHllMlZWdVdhaHJXSnpvNWkxM0NQbFpUMW52egpVQWtDMnc3dXlQZkdJU1lUTW9iWXgxcUY4UVNtOWJBMnppUEc3djZablZrQTcwdFJORGVJblY3TWErR3dmN0NJClM0anhBb0dBQlZLOVlxUGFJMWpoYTgrbjRhMzdtYlJBakRKeTJxQjVXOC9uSUcxMWIrQUZiYWZiRkFNNU42VTkKTzB6ZWFUSHNMR0xQVGtSK0dyRmdlbTdmM3dIZjN2cEhVR1R2dUVheVRVSGVKTFFKTkZMQXBWaXMra29vTmVSRQpJWFV4OWwxT2V6bjRURXJsUm5RYmtOem5pMUtZNnpRS3VXaGYyZHg0eE9xT1Fnb0JUdVE9Ci0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg=='
    def client_ro_crt(self):
        return 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVEakNDQXZhZ0F3SUJBZ0lVTXZlekNsUE1XVm84TURXREkwalZJakU5KzhRd0RRWUpLb1pJaHZjTkFRRUwKQlFBd2VqRUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdUQ0U1bGR5QlpiM0pyTVJFd0R3WURWUVFIRXdoTwpaWGNnV1c5eWF6RVZNQk1HQTFVRUNoTU1RbXh2YjIxaVpYSm5JRXhRTVNFd0h3WURWUVFMRXhoRlRrY2dRMnh2CmRXUWdTVzVtY21GemRISjFZM1IxY21VeEN6QUpCZ05WQkFNVEFtTmhNQjRYRFRFNU1EY3dOekU0TVRnd01Gb1gKRFRNMU1EY3dNekU0TVRnd01Gb3dnWUV4Q3pBSkJnTlZCQVlUQWxWVE1SRXdEd1lEVlFRSUV3aE9aWGNnV1c5eQphekVSTUE4R0ExVUVCeE1JVG1WM0lGbHZjbXN4RlRBVEJnTlZCQW9UREVKc2IyOXRZbVZ5WnlCTVVERWhNQjhHCkExVUVDeE1ZUlU1SElFTnNiM1ZrSUVsdVpuSmhjM1J5ZFdOMGRYSmxNUkl3RUFZRFZRUURFd2xqYkdsbGJuUXQKY204d2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURFNDdHdlp6SG0vL2kxL3dCNAphZ015NTFpcW9nNUtOcnEvNGw4enBsUm04K1hKOHJPYXE2bnpTNXdKdGluSkx6THJYRFJZSXIrRzMyMVNYWU9yCkRFMld1VE83akZNTC9zRTV2MmxmaUhqOGdQVGlLUVhlenpzdE5uRTEvbTVoc2tidlNMb1p4OGhVUlA4TVdRMmEKU0tFSXhzSll3NGhPOWZnbDZGVVllRFdUR09ZQVhkdGZIQmQ2Z3dONlBycVhhaXFHWWdMMG5JSmdBbW9mLzZIaQp1K0pyRTFraUJEaTBPRnFaY3NTN0Q4S0pyazRveStrQWZ0b3RuV09wS0RXRldWUDNiY3lXRDVoT1NmUVh2VURUCnM2NGpwYkJaYStnSGx6Zm5Ub2lOWDl0RlZLRHdCc1pjbnlIVllWekljSDZsdGY0TkZzYTFURXN1MVV0ZmpIbFQKNS9FQkFnTUJBQUdqZ1lNd2dZQXdEZ1lEVlIwUEFRSC9CQVFEQWdXZ01CTUdBMVVkSlFRTU1Bb0dDQ3NHQVFVRgpCd01DTUF3R0ExVWRFd0VCL3dRQ01BQXdIUVlEVlIwT0JCWUVGSm1salhKeXo3aUV4RWNaQlZnTndSdnhCVGtwCk1COEdBMVVkSXdRWU1CYUFGTGFMRGFiVlRSeFlmTy9FTHIzV3ZvMnVZQTlWTUFzR0ExVWRFUVFFTUFLQ0FEQU4KQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBZ3ZRN0V3TWFNb2FtOGlaTlRqNTVENm5OdjZSbTNoZW51M3Y0czg5NQoxaDEzMXEzYzBWWGhKT0luOGhLOXh1K0NmbnhUS2FISC9abFN1aWZ6cVpYdXBVWUVrTUREbDdZTnJid2daSkRmCmJDMDRsYko5Nkp5ZFdXRXpZT2E3V2lpNHI1MkdYWUtIWURkOW1zZWgwKzRhdW44My9PTmhyQ2NCKzdJdjQzZHEKb3MxaHVTUVljYkdrdWgxTmZBUXNnKy96N3Q0eEU4VTVxRjkzMWZRU3U0QjAzU3E4R0ZNdWc0YTk2VDhLNGxMagpkK0Jpby9zQ0dWcjE4UG1tRjhpUFVZM2dLZWNHMFNMQUhJSDhLRW9td2Y2WERWbysyYXdGdVF1by9hYWxPZEd3CkdzTWVMRGFpNU5DdldudTkzaThOL1BzQU0xUGMxb2NFRVUyN3hCb1dManF5R3c9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=='
    def client_ro_key(self):
        return 'LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBeE9PeHIyY3g1di80dGY4QWVHb0RNdWRZcXFJT1NqYTZ2K0pmTTZaVVp2UGx5Zkt6Cm1xdXA4MHVjQ2JZcHlTOHk2MXcwV0NLL2h0OXRVbDJEcXd4Tmxya3p1NHhUQy83Qk9iOXBYNGg0L0lEMDRpa0YKM3M4N0xUWnhOZjV1WWJKRzcwaTZHY2ZJVkVUL0RGa05ta2loQ01iQ1dNT0lUdlg0SmVoVkdIZzFreGptQUYzYgpYeHdYZW9NRGVqNjZsMm9xaG1JQzlKeUNZQUpxSC8raDRydmlheE5aSWdRNHREaGFtWExFdXcvQ2lhNU9LTXZwCkFIN2FMWjFqcVNnMWhWbFQ5MjNNbGcrWVRrbjBGNzFBMDdPdUk2V3dXV3ZvQjVjMzUwNklqVi9iUlZTZzhBYkcKWEo4aDFXRmN5SEIrcGJYK0RSYkd0VXhMTHRWTFg0eDVVK2Z4QVFJREFRQUJBb0lCQUF0Z2lPVDAxcHBka2phYQpES0hvcGxTcnI2RDBpbFRaZ3NNUnhxU0thUGdtQWRKQWx3WktBeUVPN201Vk8yYm50azZKWG5EMVdSSG5HVDhZCkxrS1ZER3E0T3ZnTWJNUVZyWDZ6dzlnRVg5RmZka2NYVGNLSlFRY2t6VGZzZ3Q1Y1dlTDcxZDBsZ1RyMVhiT04KOWM1RGdpS3FzWkpGZ2p2bDFMZ0VDOTdGRzN0cmEvRmZrL05JWXlDQzVkeE1LWC9Rbjk0SWxrakVRb2hZMVZ5Wgp0RWQrN3Y1dnQyNGdVZjF1Ty9VbEhWWG82NHdJZW1CU3VWK3NIdExRWXFoMW43Q3ZTSTBiS21OTG40T1J4WjduCkhGYjRwc0VLaGdlZExHQnkyeG9xckNiUkxvdWVWQno4Rk5ibVM5YlZ0VUdxWTVpNUgwejU5a0pvUWtvbjR2UXMKSlVpR3h4RUNnWUVBMllBOEIrWHZBU1hWckdoMnZocXY0SUIyTktwTzNWb2w5N3ZIS3M3VGNIaTZsKytqNEc5SwowVmJja1gwT3Q5Mlc2cEFpQjQzUWNEU2k3bk9KZ3ZiVDhLaU9qRzRhVVFYZ3cxdDBWU3BEWGlORGhISnY0bGZSCmNqSWNOemgyYzFzMkNFYVAwZWNnTkRVVWRmQU9sZGl2ckpoRWR1eVBWMW80T0kxZGZHMDdxWVVDZ1lFQTU3MTYKT1gyZGFRTVZKZWxKbHE4RGRCZmZOZmJaTjcyajBXaEZwN3hyYTVFNXZFWExXT1Q5SUIzeFhCSWRWY2RWRkhOWApmMFEwK0s0UVZBZExpaTNKcGN6REJ6UzcxT1FrS0lLajlmL0RuU2ROV0pPTmYxTHhSTzNLNzY5RkhUcjZMYUZvCk91WXM0VDhmWnFhbkxtdkVpc1l4bkh3YzFFMFFkWEhxTlUwbVpFMENnWUVBeEVpOTVFTFZscXVXVWFsVXYrdEYKbmMxUTMrWnlsY0N0VXd6YmlQNXVRcW94ZXJ5Qm9DSFAyMndRVWh3U0ZFeWR6Y0dWZEV1L09BUElwbmtPT0dxWQppaThUdGhnSEYrZStGNCtKUlBLSEtZV1pnUVhsZ3RiTjVjampQZEp1MDF3VlB4S3U2RGMxRU9oMk5wa1dFSlVrCnRSWVZjMTI1WHBQRStRUmF3ZGV5YUNFQ2dZQjdXNHRpYXhHTndzeFJIL3ZDTUd1QU11em94dndlQmQ3Y0s4dFkKWEo0NTVsWjdlQk9rd0ZCVjlscHlqbG43UFY1MndtZERJY1dvMHM5eVMyZlVxRWI4OFNDb0IxUXRJVHgyTEFTbgpnSHhhZlg5WXRVTFBFaEhJaFdSUGJsYzJGaHp5aVViNGcycEVoTnRzUXk0Zk1kS3ZwSXpvSmRFYTJlTDNBYXFRCnNQN015UUtCZ0JQeHp2TXE5dmV2b2FzejNyaXc0d1VvWlhyYlBhQXRXdjlYU0loRWd1Uk1Xa3NyRVRmd1lmVkIKS1FNQk91dFpoS00vSk5uMDJnV3BJTDVZSFU5SFZqNFFzeERteXl3OXg3WUgvOTVCK2xvZ3docEIyOWhabFJScgplUzZrQ09BNmdSdjdUa2prdlRNNXVYSEVremludUp0MGZpd0N1TFQ5VGxpR01yZWNtVDFWCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg=='
    def client_rw_crt(self):
        return 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVEakNDQXZhZ0F3SUJBZ0lVWk8rbW1ITURMWStqeWJBR0loV3MyWmFsZFFvd0RRWUpLb1pJaHZjTkFRRUwKQlFBd2VqRUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdUQ0U1bGR5QlpiM0pyTVJFd0R3WURWUVFIRXdoTwpaWGNnV1c5eWF6RVZNQk1HQTFVRUNoTU1RbXh2YjIxaVpYSm5JRXhRTVNFd0h3WURWUVFMRXhoRlRrY2dRMnh2CmRXUWdTVzVtY21GemRISjFZM1IxY21VeEN6QUpCZ05WQkFNVEFtTmhNQjRYRFRFNU1EY3dOekU0TVRnd01Gb1gKRFRNMU1EY3dNekU0TVRnd01Gb3dnWUV4Q3pBSkJnTlZCQVlUQWxWVE1SRXdEd1lEVlFRSUV3aE9aWGNnV1c5eQphekVSTUE4R0ExVUVCeE1JVG1WM0lGbHZjbXN4RlRBVEJnTlZCQW9UREVKc2IyOXRZbVZ5WnlCTVVERWhNQjhHCkExVUVDeE1ZUlU1SElFTnNiM1ZrSUVsdVpuSmhjM1J5ZFdOMGRYSmxNUkl3RUFZRFZRUURFd2xqYkdsbGJuUXQKY25jd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUN0Z1laSTU2Yk5lc2Z2ekt0bQprM1czN3VLSG9JMnhZNzhRcHZ4VkM4aWNhdFQyVHF6SlhXbW9TUitHdlBHOEdxVzhVU0RPM3lPY2kxQnVjL1pzCitoZjhxV0hHVTY3V0xOL1c1bDVEZGVFengrNVdQM3dmUTRzeVNVZGhFWE5abjZaSzZTMGZHa1BGRndhYWJOY0sKMVJ2bGhiWW9QNFd2VXhhQitvdG4wS252czBzKyt6dXdqczhPVDFwaVNkY25aZVpJUmVlRTFJcjFteXNNVkJLNwpYM1RKL2FtV2MweGFqQmk0RHUvUnpENTVKUHJ3cE5ocTZCWHVaTHhiekdoTjBkQ3lFOUN4bGtYYU5jc1J6Nm9oCmdwVlNXV2szZzA5d1plKzVCaURpZmFtSklrb0I4MHpIRzJYU3hzeUc3bi9PNGtXMHliVHBxTkFQbzdIcmZJQUoKTEFleEFnTUJBQUdqZ1lNd2dZQXdEZ1lEVlIwUEFRSC9CQVFEQWdXZ01CTUdBMVVkSlFRTU1Bb0dDQ3NHQVFVRgpCd01DTUF3R0ExVWRFd0VCL3dRQ01BQXdIUVlEVlIwT0JCWUVGTFJ1UzlsbUhPbUZVL2JzZ3llR1l2ZG9MVnZzCk1COEdBMVVkSXdRWU1CYUFGTGFMRGFiVlRSeFlmTy9FTHIzV3ZvMnVZQTlWTUFzR0ExVWRFUVFFTUFLQ0FEQU4KQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBTjNSbFJXMHVnbDZxT2FxZzZGMGlrZWtVTlFCK0UxTmx5VC9NUW9hMgpJVWgyVTAwSzFtbnBZcjRaMHdXMUo5Q3p0T2VUWUNxMHlURko2UlZVMEZxbUk5SENpYzB4MXAwOGZjeEhFZFpTCk53aG95a2JGM2U4cGh5SDY4SFl3WHZvc1hsbzJOb0p0dnVrUWxQMmQvZk1mNUh3b0s3c1M2dHU1UGErMUJtU0sKRWxXajI1eWhSK0NtZWk2RytRTWxQRlZaMTFNTVU3OTIxTjdqeTdVaVhlalBKQ25GM1hBbjMzUmh4TWd0ZEJqUgpYZ0MwNVhLN2RWaEVsQVVmRGpTSHNLRWhTaS9pTFM0NGZCOTZrQnUrdUtuKzNyY3VRWklnMElxaDJteGNveWhsCkQ2NEJLbm9NVTM5UHU3cUZGNkpMaEpzSFN6dzhxK1dORjVQV20vVjFrejhKdlE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=='
    def client_rw_key(self):
        return 'LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBcllHR1NPZW16WHJINzh5clpwTjF0KzdpaDZDTnNXTy9FS2I4VlF2SW5HclU5azZzCnlWMXBxRWtmaHJ6eHZCcWx2RkVnenQ4am5JdFFiblAyYlBvWC9LbGh4bE91MWl6ZjF1WmVRM1hoTThmdVZqOTgKSDBPTE1rbEhZUkZ6V1orbVN1a3RIeHBEeFJjR21telhDdFViNVlXMktEK0ZyMU1XZ2ZxTFo5Q3A3N05MUHZzNwpzSTdQRGs5YVlrblhKMlhtU0VYbmhOU0s5WnNyREZRU3UxOTB5ZjJwbG5OTVdvd1l1QTd2MGN3K2VTVDY4S1RZCmF1Z1Y3bVM4Vzh4b1RkSFFzaFBRc1paRjJqWExFYytxSVlLVlVsbHBONE5QY0dYdnVRWWc0bjJwaVNKS0FmTk0KeHh0bDBzYk1odTUvenVKRnRNbTA2YWpRRDZPeDYzeUFDU3dIc1FJREFRQUJBb0lCQUMwYzBGMkVYY3B2Y2l6WAplbmxoUGVwbEltRkJUWlloNlR2Ykx5Q3R2NnRyMjVOdlFWM1orKzdWbEd6a0U3Wms5MUxQaFVoRW5HM0hpMUlzCnRKWUJNTnR3N3dzeUZ2TjVGM280eTZtZXJMOVo3STVnVTFXTnFsT1kyZ1pURXpycVY4S0Nma2puKzFiemRiUVIKT0ppSWNJaHRDNy9MUkdjaG8yaUlURmJoMmsySVV4OVpveE5EQnlrUmFrMWZHTjNpQUVJR1l0TGtJVGNScmtYbgpMYXNka1N2Tlh6S3RQbUV0LzZWSDcyblJlRVNpZGJNbXBwUzBRTjBwdlM4RU8xL2hERGpYTWtSVHI0byt1SC9BCmlGMG5MYUQ1anRKL3diZUVmR3AxL0JKaElZYlZzWDRIME5rSitycXNXZ2ZVRS9LWmpQRkkvdlhTdkU4U0ZzbWUKY2hoZ1VFRUNnWUVBMGdMM1YvSUFQV1VLYW5GdnRCWHFTUXlOYVdIZUIwQUpSVW5tR1VXNUFyb1dyT1p2RWxJLwpZWnk5RC84Q0lGV1V2MHZUTTB3aUNHV0trbW9uZDRueTV6ODZPMUc3M0h1WDRoMjdFdEQrYXNCMGNMZmZPWjdUCm5SZko0QW42MEFNV1BVK2pqNXBkdWQyOFhUVldIRHdZMHdzZGVYaDk2WlM1RitrS3cwNUI5dDhDZ1lFQTA0QVgKRlU3dVVvQkd6MFNhR25YTDdYVlBuYm9PQW5XV0pOMUZEcFFDVXljOW1PNVR4bTk1cHpGU0MwNFd4Q1dReklHSgozZXNycGVsUzZ0Vi94RHZmTmZyWjVib2xIRDE0bkV2c0ZnYjMzWWI0TkN2RmJ5RUs3cVkvUjdEa0pLUTUxaE5JCmkyZDRZdzJ4Yk5vb01tKzZ5cmZFQnBQQmxYSkpka0lRc0p2ZW8yOENnWUJUY3B4SDFNQWxwUlY3Y0RHYmxDMncKOHd6cHQ5cWFkT1o2SXNBTWdMamdEWU5mRm4xQ0FXNXY0ZkQ1L3pFZ0dnRnQ5Ym9wSXZKTzlkSVhGWmt6Rlp4dwpLSjZCM1p0Ukk4Y1pNUWtaay9QVUJUNy9Yd0NUQzdvNExMQ3BsaTJVSS9YZFROekgvZVdLS2tKam93TGhXenZkCitBZXhNYUNPaE9yN1JqMWhsNkg4YndLQmdHOU1vTmtkeUZ5eUZKRk9VS3BNQXh6YTl5TFJuajI5RTE0aTh3eFEKNTBoTEJpZE1nOW1SSUR2VHdKRWlidWladkRGaW1lS210em1BSjVwYzcvZWNha0pGMkJVRWVETDhSbFE1dit0MwpqMGlNbG1FZUI3QUxlMjFMSDFIaXpLeGJuL1FBQWRVYWhrZmFGTnhya1d1NVVGc05pYUxNYnJydWdhb3g2Z2FHCmdBc1JBb0dCQUl0VkdkQ1N2Z1d4NHpnTkRrSWhmR0RrUkYwSUgzTldVdXR5cjdDTWIyeHJVazI2Z0Z3bFRaamsKV2U3eFVJTnUxUExiRjFKZ3oxaGk5MnNsVnc3bUVjeEo2WGh0RFdmR1FkK3pCMkR5ZWFPbEx1VTMvVWdleGZMdApsTG1ObytoYTZLNkNiV3F5N2ZXTVVmNFQxaEtCMEM2aVNZRDB5VjMveWtsSlZzSXVrZitSCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg=='

class SSH:
    def __init__(self):
        self.__key = RSA.generate(1024)

    @property
    def key(self):
        return self.__key

    def public(self):
        key = self.key.publickey().exportKey('OpenSSH')
        return base64.b64encode(key).decode()

    def private(self):
        key = self.key.exportKey('PEM')
        return base64.b64encode(key).decode()

class BCCChefDatabags:

    def __init__(self):
        self.__etcd_ssl = EtcdSSL()
        self.__nova_ssh = SSH()
        self.__ssh = SSH()
        self.__ssl = SSL()

    @property
    def etcd_ssl(self):
        return self.__etcd_ssl

    @property
    def nova_ssh(self):
        return self.__nova_ssh

    @property
    def ssh(self):
        return self.__ssh

    @property
    def ssl(self):
        return self.__ssl

    def generate_ceph_key(self):
        key = os.urandom(16)
        header = struct.pack('<hiih',1,int(time.time()),0,len(key))
        return base64.b64encode(header + key).decode()

    def generate_fernet(self):
        return base64.urlsafe_b64encode(os.urandom(32)).decode()

    def generate_string(self,length=32):
        return ''.join((secrets.choice(string.ascii_letters) for i in range(length)))

    def generate_uuid(self):
        return str(uuid.uuid4())

    def save(self, force=False):
        cmd = 'git rev-parse --show-toplevel'
        root = subprocess.check_output(cmd.split(" ")).decode().rstrip('\n')
        fp = '{0}/{1}'.format(root,'ansible/group_vars/all/chef_databags.yml')

        if os.path.isfile(fp) and not force:
            msg = '{} exists.\nWill not overwrite without force.'
            msg = msg.format(fp)
            raise FileExistsError(msg)

        with open(fp, 'w') as file:
            yaml.dump(self.generate(), file, default_flow_style=False, indent=2)

    def generate(self):

        config = {
            'id': 'config',
            'openstack': {
                'admin': {
                    'password': self.generate_string()
                }
            },
            'ceph': {
                'fsid': self.generate_uuid(),
                'mon': {
                    'key': self.generate_ceph_key()
                },
                'bootstrap': {
                    'mds': {
                        'key': self.generate_ceph_key()
                    },
                    'mgr': {
                        'key': self.generate_ceph_key()
                    },
                    'osd': {
                        'key': self.generate_ceph_key()
                    },
                    'rgw': {
                        'key': self.generate_ceph_key()
                    },
                    'rbd': {
                        'key': self.generate_ceph_key()
                    },
                },
                'client': {
                    'admin': {
                        'key': self.generate_ceph_key()
                    },
                    'cinder': {
                        'key': self.generate_ceph_key()
                    },
                    'glance': {
                        'key': self.generate_ceph_key()
                    }
                },
            },
            'etcd': {
                'users': [
                    {'username': 'root', 'password': self.generate_string()},
                    {'username': 'server', 'password': self.generate_string()},
                    {'username': 'client-ro', 'password': self.generate_string()},
                    {'username': 'client-rw', 'password': self.generate_string()},
                ],
                'ssl': {
                    'ca': {
                        'crt': self.etcd_ssl.ca_crt(),
                    },
                    'server': {
                        'crt': self.etcd_ssl.server_crt(),
                        'key': self.etcd_ssl.server_key(),
                    },
                    'client-ro': {
                        'crt': self.etcd_ssl.client_ro_crt(),
                        'key': self.etcd_ssl.client_ro_key(),
                    },
                    'client-rw': {
                        'crt': self.etcd_ssl.client_rw_crt(),
                        'key': self.etcd_ssl.client_rw_key(),
                    },
                }
            },
            'powerdns': {
                'creds': {
                    'db': { 'username': 'pdns', 'password': self.generate_string() },
                    'webserver': {'password': self.generate_string() },
                    'api': {'key': self.generate_string() },
                }
            },
            'keystone': {
                'db': { 'username': 'keystone', 'password': self.generate_string() },
                'fernet': {
                    'keys': {
                        'primary': self.generate_fernet(),
                        'secondary': self.generate_fernet(),
                        'staged': self.generate_fernet(),
                    }
                }
            },
            'glance': {
                'creds': {
                    'db': { 'username': 'glance', 'password': self.generate_string() },
                    'os': { 'username': 'glance', 'password': self.generate_string() },
                }
            },
            'cinder': {
                'creds': {
                    'db': { 'username': 'cinder', 'password': self.generate_string() },
                    'os': { 'username': 'cinder', 'password': self.generate_string() },
                }
            },
            'heat': {
                'creds': {
                    'db': { 'username': 'heat', 'password': self.generate_string() },
                    'os': { 'username': 'heat', 'password': self.generate_string() },
                }
            },
            'horizon': { 'secret': self.generate_string() },
            'libvirt': { 'secret': self.generate_uuid() },
            'neutron': {
                'creds': {
                    'db': { 'username': 'neutron', 'password': self.generate_string() },
                    'os': { 'username': 'neutron', 'password': self.generate_string() },
                }
            },
            'nova': {
                'creds': {
                    'db': { 'username': 'neutron', 'password': self.generate_string() },
                    'os': { 'username': 'neutron', 'password': self.generate_string() },
                },
                'ssh': {
                    'crt': self.nova_ssh.public(),
                    'key': self.nova_ssh.private()
                }
            },
            'placement': {
                'creds': {
                    'os': { 'username': 'placement', 'password': self.generate_string() },
                }
            },
            'mysql': {
                'users': {
                    'sst': { 'password': self.generate_string() },
                    'root': { 'password': self.generate_string() },
                    'check': { 'password': self.generate_string() },
                }
            },
            'rabbit': {
                'username': 'guest',
                'password': self.generate_string(),
                'cookie': self.generate_string()
            },
            'haproxy': {
                'username': 'haproxy',
                'password': self.generate_string(),
            },
            'ssh': {
                'public': self.ssh.public(),
                'private': self.ssh.private()
            },
            'ssl': {
                'key': self.ssl.key(),
                'crt': self.ssl.crt(),
                'intermediate': None
            }
        }

        zones = {
            'id': 'zones',
            'dev': {
                'ceph': {
                    'client': {
                        'cinder': { 'key': self.generate_ceph_key() }
                    }
                },
                'libvirt': { 'secret': self.generate_uuid() }
            }
        }

        return { 'chef_databags': [config,zones] }
