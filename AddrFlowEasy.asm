;esp : 0x0019F900
;ebp : 0x0019FA7C
/*0x00401660*/    push ebp
;esp : 0x0019F8FC
/*0x00401661*/    mov ebp, esp
;ebp : 0x0019F8FC
/*0x00401663*/    push 0xFFFFFFFF
;esp : 0x0019F8F8
/*0x00401665*/    push 0x40553D
;esp : 0x0019F8F4
/*0x0040166A*/    mov eax, dword ptr fs:[0x00000000]
/*0x00401670*/    push eax
;esp : 0x0019F8F0
/*0x00401671*/    sub esp, 0x40
;esp : 0x0019F8B0
/*0x00401674*/    mov eax, dword ptr ds:[0x00409000]
;[0x00409000]=[0x00409000]=0xB3BEA9D5
/*0x00401679*/    xor eax, ebp
/*0x0040167B*/    mov dword ptr ss:[ebp-0x14], eax
;[ebp-0x14]=[0x0019F8E8]=0xBF000000
;[ebp-0x14]=[0x0019F8E8]=0xB3A75129  <-- Modify
/*0x0040167E*/    push ebx
;esp : 0x0019F8AC
/*0x0040167F*/    push esi
;esp : 0x0019F8A8
/*0x00401680*/    push edi
;esp : 0x0019F8A4
/*0x00401681*/    push eax
;esp : 0x0019F8A0
/*0x00401682*/    lea eax, ss:[ebp-0xC]
;[ebp-0xC]=[0x0019F8F0]=0x0019FA70
/*0x00401685*/    mov dword ptr fs:[0x00000000], eax
/*0x0040168B*/    mov dword ptr ss:[ebp-0x10], esp
;[ebp-0x10]=[0x0019F8EC]=0x52E2651C
;[ebp-0x10]=[0x0019F8EC]=0x0019F8A0  <-- Modify
/*0x0040168E*/    mov esi, ecx
/*0x00401690*/    mov dword ptr ss:[ebp-0x24], esi
;[ebp-0x24]=[0x0019F8D8]=0xBF800000
;[ebp-0x24]=[0x0019F8D8]=0x08A5A8E8  <-- Modify
/*0x00401693*/    mov ecx, dword ptr ss:[ebp+0x8]
;[ebp+0x8]=[0x0019F904]=0x08A87EF4
/*0x00401696*/    mov eax, dword ptr ss:[ebp+0xC]
;[ebp+0xC]=[0x0019F908]=0x0019F950
/*0x00401699*/    mov edi, dword ptr ds:[esi]
;[esi]=[0x08A5A8E8]=0x08A87DD8
/*0x0040169B*/    mov dword ptr ss:[ebp-0x2C], eax
;[ebp-0x2C]=[0x0019F8D0]=0x80000000
;[ebp-0x2C]=[0x0019F8D0]=0x0019F950  <-- Modify
/*0x0040169E*/    mov eax, 0xE6C2B449
/*0x004016A3*/    mov dword ptr ss:[ebp-0x30], ecx
;[ebp-0x30]=[0x0019F8CC]=0x3F800000
;[ebp-0x30]=[0x0019F8CC]=0x08A87EF4  <-- Modify
/*0x004016A6*/    sub ecx, edi
/*0x004016A8*/    imul ecx
/*0x004016AA*/    add edx, ecx
/*0x004016AC*/    mov ecx, dword ptr ds:[esi+0x4]
;[esi+0x4]=[0x08A5A8EC]=0x08A87EF4
/*0x004016AF*/    sar edx, 0x8
/*0x004016B2*/    sub ecx, edi
/*0x004016B4*/    mov eax, edx
/*0x004016B6*/    shr eax, 0x1F
/*0x004016B9*/    add eax, edx
/*0x004016BB*/    mov dword ptr ss:[ebp-0x28], eax
;[ebp-0x28]=[0x0019F8D4]=0x3F800000
;[ebp-0x28]=[0x0019F8D4]=0x00000001  <-- Modify
/*0x004016BE*/    mov eax, 0xE6C2B449
/*0x004016C3*/    imul ecx
/*0x004016C5*/    add edx, ecx
/*0x004016C7*/    sar edx, 0x8
/*0x004016CA*/    mov eax, edx
/*0x004016CC*/    shr eax, 0x1F
/*0x004016CF*/    add eax, edx
/*0x004016D1*/    cmp eax, 0xE6C2B4
;/*0x004016D6*/    je 0x00401981
/*0x004016DC*/    mov ecx, dword ptr ds:[esi+0x8]
;[esi+0x8]=[0x08A5A8F0]=0x08A87EF4
/*0x004016DF*/    lea ebx, ds:[eax+0x1]
/*0x004016E2*/    sub ecx, edi
/*0x004016E4*/    mov dword ptr ss:[ebp-0x40], ebx
;[ebp-0x40]=[0x0019F8BC]=0x00000000
;[ebp-0x40]=[0x0019F8BC]=0x00000002  <-- Modify
/*0x004016E7*/    mov eax, 0xE6C2B449
/*0x004016EC*/    imul ecx
/*0x004016EE*/    mov eax, 0xE6C2B4
/*0x004016F3*/    add edx, ecx
/*0x004016F5*/    sar edx, 0x8
/*0x004016F8*/    mov ecx, edx
/*0x004016FA*/    shr ecx, 0x1F
/*0x004016FD*/    add ecx, edx
/*0x004016FF*/    mov edx, ecx
/*0x00401701*/    shr edx, 0x1
/*0x00401703*/    sub eax, edx
/*0x00401705*/    cmp ecx, eax
;/*0x00401707*/    jbe 0x0040171D
/*0x0040171D*/    lea eax, ds:[edx+ecx*1]
/*0x00401720*/    mov esi, ebx
/*0x00401722*/    cmp eax, ebx
/*0x00401724*/    cmovae esi, eax
/*0x00401727*/    cmp esi, 0xE6C2B4
;/*0x0040172D*/    ja 0x0040197C
/*0x00401733*/    imul ebx, esi, 0x11C
/*0x00401739*/    mov dword ptr ss:[ebp-0x34], esi
;[ebp-0x34]=[0x0019F8C8]=0x80000000
;[ebp-0x34]=[0x0019F8C8]=0x00000002  <-- Modify
/*0x0040173C*/    mov dword ptr ss:[ebp-0x3C], ebx
;[ebp-0x3C]=[0x0019F8C0]=0x80000000
;[ebp-0x3C]=[0x0019F8C0]=0x00000238  <-- Modify
/*0x0040173F*/    cmp ebx, 0x1000
;/*0x00401745*/    jb 0x0040176E
/*0x0040176E*/    test ebx, ebx
;/*0x00401770*/    je 0x00401785
/*0x00401772*/    push ebx
;esp : 0x0019F89C
/*0x00401773*/    call 0x0040474B
/*0x00401778*/    add esp, 0x4
;esp : 0x0019F8A0
/*0x0040177B*/    mov dword ptr ss:[ebp-0x38], eax
;[ebp-0x38]=[0x0019F8C4]=0x00004003
;[ebp-0x38]=[0x0019F8C4]=0x08A760E8  <-- Modify
/*0x0040177E*/    mov ebx, eax
/*0x00401780*/    mov dword ptr ss:[ebp-0x34], esi
;[ebp-0x34]=[0x0019F8C8]=0x00000002
;/*0x00401783*/    jmp 0x0040178D
/*0x0040178D*/    imul esi, dword ptr ss:[ebp-0x28], 0x11C
;[ebp-0x28]=[0x0019F8D4]=0x00000001
/*0x00401794*/    push dword ptr ss:[ebp-0x2C]
;[ebp-0x2C]=[0x0019F8D0]=0x0019F950
;esp : 0x0019F89C
/*0x00401797*/    mov dword ptr ss:[ebp-0x4C], ebx
;[ebp-0x4C]=[0x0019F8B0]=0x00000000
;[ebp-0x4C]=[0x0019F8B0]=0x08A760E8  <-- Modify
/*0x0040179A*/    mov dword ptr ss:[ebp-0x4], 0x0
;[ebp-0x4]=[0x0019F8F8]=0xFFFFFFFF
;[ebp-0x4]=[0x0019F8F8]=0x00000000  <-- Modify
/*0x004017A1*/    add esi, ebx
/*0x004017A3*/    mov ecx, esi
/*0x004017A5*/    mov dword ptr ss:[ebp-0x44], esi
;[ebp-0x44]=[0x0019F8B8]=0x40048000
;[ebp-0x44]=[0x0019F8B8]=0x08A76204  <-- Modify
/*0x004017A8*/    lea edi, ds:[esi+0x11C]
;[esi+0x11C]=[0x08A76320]=0xABABABAB
/*0x004017AE*/    mov dword ptr ss:[ebp-0x48], edi
;[ebp-0x48]=[0x0019F8B4]=0x00000000
;[ebp-0x48]=[0x0019F8B4]=0x08A76320  <-- Modify
/*0x004017B1*/    mov dword ptr ss:[ebp-0x28], edi
;[ebp-0x28]=[0x0019F8D4]=0x00000001
;[ebp-0x28]=[0x0019F8D4]=0x08A76320  <-- Modify
/*0x004017B4*/    call dword ptr ds:[0x00406160]
;[0x00406160]=[0x00406160]=0x52E26D90
;esp : 0x0019F8A0
/*0x004017BA*/    mov edx, dword ptr ss:[ebp-0x24]
;[ebp-0x24]=[0x0019F8D8]=0x08A5A8E8
/*0x004017BD*/    xorps xmm0, xmm0
/*0x004017C0*/    mov eax, dword ptr ss:[ebp-0x30]
;[ebp-0x30]=[0x0019F8CC]=0x08A87EF4
/*0x004017C3*/    mov dword ptr ds:[esi], 0x4062C4
;[esi]=[0x08A76204]=0x52E81F90
;[esi]=[0x08A76204]=0x004062C4  <-- Modify
/*0x004017C9*/    mov dword ptr ds:[esi+0x4], 0x4062EC
;[esi+0x4]=[0x08A76208]=0x52E81FA4
;[esi+0x4]=[0x08A76208]=0x004062EC  <-- Modify
/*0x004017D0*/    mov ecx, dword ptr ds:[edx+0x4]
;[edx+0x4]=[0x08A5A8EC]=0x08A87EF4
/*0x004017D3*/    mov dword ptr ss:[ebp-0x28], esi
;[ebp-0x28]=[0x0019F8D4]=0x08A76320
;[ebp-0x28]=[0x0019F8D4]=0x08A76204  <-- Modify
/*0x004017D6*/    mov esi, dword ptr ds:[edx]
;[edx]=[0x08A5A8E8]=0x08A87DD8
/*0x004017D8*/    mov dword ptr ss:[ebp-0x18], 0x0
;[ebp-0x18]=[0x0019F8E4]=0x80000000
;[ebp-0x18]=[0x0019F8E4]=0x00000000  <-- Modify
/*0x004017DF*/    movq qword ptr ss:[ebp-0x20], xmm0
;[ebp-0x20]=[0x0019F8DC]=0x80000000
;[ebp-0x20]=[0x0019F8DC]=0x00000000  <-- Modify
/*0x004017E4*/    mov dword ptr ss:[ebp-0x2C], ecx
;[ebp-0x2C]=[0x0019F8D0]=0x0019F950
;[ebp-0x2C]=[0x0019F8D0]=0x08A87EF4  <-- Modify
/*0x004017E7*/    mov dword ptr ss:[ebp-0x18], edx
;[ebp-0x18]=[0x0019F8E4]=0x00000000
;[ebp-0x18]=[0x0019F8E4]=0x08A5A8E8  <-- Modify
/*0x004017EA*/    mov dword ptr ss:[ebp-0x20], ebx
;[ebp-0x20]=[0x0019F8DC]=0x00000000
;[ebp-0x20]=[0x0019F8DC]=0x08A760E8  <-- Modify
/*0x004017ED*/    cmp eax, ecx
;/*0x004017EF*/    jne 0x00401832
/*0x004017F1*/    mov edi, ebx
/*0x004017F3*/    mov dword ptr ss:[ebp-0x1C], edi
;[ebp-0x1C]=[0x0019F8E0]=0x00000000
;[ebp-0x1C]=[0x0019F8E0]=0x08A760E8  <-- Modify
/*0x004017F6*/    mov byte ptr ss:[ebp-0x4], 0x1
;[ebp-0x4]=[0x0019F8F8]=0x00000000
;[ebp-0x4]=[0x0019F8F8]=0x00000001  <-- Modify
/*0x004017FA*/    nop word ptr ds:[eax+eax*1], ax
;[eax+eax*1]=[0x1150FDE8]=0x08A87EF4
/*0x00401800*/    cmp esi, ecx
;/*0x00401802*/    je 0x004018D3
/*0x00401808*/    push esi
;esp : 0x0019F89C
/*0x00401809*/    mov ecx, edi
/*0x0040180B*/    call dword ptr ds:[0x00406160]
;[0x00406160]=[0x00406160]=0x52E26D90
;esp : 0x0019F8A0
/*0x00401811*/    mov ecx, dword ptr ss:[ebp-0x2C]
;[ebp-0x2C]=[0x0019F8D0]=0x08A87EF4
/*0x00401814*/    mov dword ptr ds:[edi], 0x4062C4
;[edi]=[0x08A760E8]=0x52E81F90
;[edi]=[0x08A760E8]=0x004062C4  <-- Modify
/*0x0040181A*/    mov dword ptr ds:[edi+0x4], 0x4062EC
;[edi+0x4]=[0x08A760EC]=0x52E81FA4
;[edi+0x4]=[0x08A760EC]=0x004062EC  <-- Modify
/*0x00401821*/    add edi, 0x11C
/*0x00401827*/    mov dword ptr ss:[ebp-0x1C], edi
;[ebp-0x1C]=[0x0019F8E0]=0x08A760E8
;[ebp-0x1C]=[0x0019F8E0]=0x08A76204  <-- Modify
/*0x0040182A*/    add esi, 0x11C
;/*0x00401830*/    jmp 0x00401800;GOTO BACK
/*0x004018D3*/    mov edx, dword ptr ss:[ebp-0x24]
;[ebp-0x24]=[0x0019F8D8]=0x08A5A8E8
/*0x004018D6*/    mov esi, dword ptr ds:[edx]
;[edx]=[0x08A5A8E8]=0x08A87DD8
/*0x004018D8*/    test esi, esi
;/*0x004018DA*/    je 0x0040193F
/*0x004018DC*/    mov edi, dword ptr ds:[edx+0x4]
;[edx+0x4]=[0x08A5A8EC]=0x08A87EF4
/*0x004018DF*/    cmp esi, edi
;/*0x004018E1*/    je 0x004018F8
/*0x004018E3*/    mov eax, dword ptr ds:[esi]
;[esi]=[0x08A87DD8]=0x004062C4
/*0x004018E5*/    mov ecx, esi
/*0x004018E7*/    push 0x0
;esp : 0x0019F89C
/*0x004018E9*/    call dword ptr ds:[eax]
;[eax]=[0x004062C4]=0x00401B40
;esp : 0x0019F898
/*0x00401B40*/    push ebp
;esp : 0x0019F894
/*0x00401B41*/    mov ebp, esp
;ebp : 0x0019F894
/*0x00401B43*/    push esi
;esp : 0x0019F890
/*0x00401B44*/    mov esi, ecx
/*0x00401B46*/    call dword ptr ds:[0x0040615C]
;[0x0040615C]=[0x0040615C]=0x52E26B50
/*0x00401B4C*/    test byte ptr ss:[ebp+0x8], 0x1
;[ebp+0x8]=[0x0019F89C]=0x00000000
;/*0x00401B50*/    je 0x00401B60
/*0x00401B60*/    mov eax, esi
/*0x00401B62*/    pop esi
;esp : 0x0019F894
/*0x00401B63*/    pop ebp
;esp : 0x0019F898
;ebp : 0x0019F8FC
/*0x00401B64*/    ret 0x4
;esp : 0x0019F8A0
/*0x004018EB*/    add esi, 0x11C
/*0x004018F1*/    cmp esi, edi
;/*0x004018F3*/    jne 0x004018E3;GOTO BACK
/*0x004018F5*/    mov edx, dword ptr ss:[ebp-0x24]
;[ebp-0x24]=[0x0019F8D8]=0x08A5A8E8
/*0x004018F8*/    mov ecx, dword ptr ds:[edx+0x8]
;[edx+0x8]=[0x08A5A8F0]=0x08A87EF4
/*0x004018FB*/    mov eax, 0xE6C2B449
/*0x00401900*/    mov esi, dword ptr ds:[edx]
;[edx]=[0x08A5A8E8]=0x08A87DD8
/*0x00401902*/    sub ecx, esi
/*0x00401904*/    imul ecx
/*0x00401906*/    add edx, ecx
/*0x00401908*/    sar edx, 0x8
/*0x0040190B*/    mov eax, edx
/*0x0040190D*/    shr eax, 0x1F
/*0x00401910*/    add eax, edx
/*0x00401912*/    imul ecx, eax, 0x11C
/*0x00401918*/    cmp ecx, 0x1000
;/*0x0040191E*/    jb 0x00401932
/*0x00401932*/    push ecx
;esp : 0x0019F89C
/*0x00401933*/    push esi
;esp : 0x0019F898
/*0x00401934*/    call 0x0040477B
/*0x00401939*/    mov edx, dword ptr ss:[ebp-0x24]
;[ebp-0x24]=[0x0019F8D8]=0x08A5A8E8
/*0x0040193C*/    add esp, 0x8
;esp : 0x0019F8A0
/*0x0040193F*/    imul ecx, dword ptr ss:[ebp-0x40], 0x11C
;[ebp-0x40]=[0x0019F8BC]=0x00000002
/*0x00401946*/    mov eax, dword ptr ss:[ebp-0x44]
;[ebp-0x44]=[0x0019F8B8]=0x08A76204
/*0x00401949*/    mov dword ptr ds:[edx], ebx
;[edx]=[0x08A5A8E8]=0x08A87DD8
;[edx]=[0x08A5A8E8]=0x08A760E8  <-- Modify
/*0x0040194B*/    add ecx, ebx
/*0x0040194D*/    mov dword ptr ds:[edx+0x4], ecx
;[edx+0x4]=[0x08A5A8EC]=0x08A87EF4
;[edx+0x4]=[0x08A5A8EC]=0x08A76320  <-- Modify
/*0x00401950*/    mov ecx, dword ptr ss:[ebp-0x3C]
;[ebp-0x3C]=[0x0019F8C0]=0x00000238
/*0x00401953*/    add ecx, ebx
/*0x00401955*/    mov dword ptr ds:[edx+0x8], ecx
;[edx+0x8]=[0x08A5A8F0]=0x08A87EF4
;[edx+0x8]=[0x08A5A8F0]=0x08A76320  <-- Modify
/*0x00401958*/    mov ecx, dword ptr ss:[ebp-0xC]
;[ebp-0xC]=[0x0019F8F0]=0x0019FA70
/*0x0040195B*/    mov dword ptr fs:[0x00000000], ecx
/*0x00401962*/    pop ecx
;esp : 0x0019F8A4
/*0x00401963*/    pop edi
;esp : 0x0019F8A8
/*0x00401964*/    pop esi
;esp : 0x0019F8AC
/*0x00401965*/    pop ebx
;esp : 0x0019F8B0
/*0x00401966*/    mov ecx, dword ptr ss:[ebp-0x14]
;[ebp-0x14]=[0x0019F8E8]=0xB3A75129
/*0x00401969*/    xor ecx, ebp
/*0x0040196B*/    call 0x0040473D
/*0x00401970*/    mov esp, ebp
;esp : 0x0019F8FC
/*0x00401972*/    pop ebp
;esp : 0x0019F900
;ebp : 0x0019FA7C
/*0x00401973*/    ret 0x8
