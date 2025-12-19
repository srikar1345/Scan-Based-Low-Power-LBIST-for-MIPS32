
library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.NUMERIC_STD.ALL;

----------------------------------------------------------------------------------
-- Component: MISR (Multiple Input Signature Register)
----------------------------------------------------------------------------------

entity MISR is
    generic(
        W : integer := 32    -- width of MISR
    );
    port(
        clk     : in  std_logic;
        rst     : in  std_logic;
        enable  : in  std_logic; -- Control signal (linked to lbist_en)
        din     : in  std_logic_vector(W-1 downto 0);    -- Input from Scan Cells
        sig_out : out std_logic_vector(W-1 downto 0)     -- MISR signature
    );
end entity;

architecture Behavioral of MISR is
    signal r : std_logic_vector(W-1 downto 0); -- Internal register for the signature
begin
    process(clk, rst)
    begin
        if rst = '1' then
            r <= (others => '0');
        elsif rising_edge(clk) then
            if enable = '1' then
                -- Rotate-right MISR with XOR input:
                r <= (r(0) & r(W-1 downto 1)) xor din;
            end if;
        end if;
    end process;

    sig_out <= r;
end architecture;


-- lfsr40.vhd
--library ieee;
--use ieee.std_logic_1164.all;
--use ieee.numeric_std.all;

-- lfsr40.vhd  -- fixed version
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity lfsr40 is
    port (
        clk       : in  std_logic;
        rst       : in  std_logic;          -- synchronous active-high reset (clears to seed)
        load_seed : in  std_logic;          -- synchronous load enable for seed
        seed      : in  std_logic_vector(39 downto 0); -- seed; must not be all '0'
        enable    : in  std_logic;          -- enable shifting
        lfsr_vec  : out std_logic_vector(39 downto 0)  -- MSB at index 39
    );
end entity;

architecture rtl of lfsr40 is
    signal lfsr_q : std_logic_vector(39 downto 0) := (others => '0');
    signal feedback_xnor : std_logic;
    constant DEFAULT_SEED : std_logic_vector(39 downto 0) := x"ABCDEFFF01"; -- 10 hex digits => 40 bits
begin

    ----------------------------------------------------------------------------
    -- feedback (concurrent) for polynomial x^40 + x^38 + x^21 + x^19 + 1
    -- mapping: use indices 39 (x^40), 37 (x^38), 20 (x^21), 18 (x^19)
    ----------------------------------------------------------------------------
    -- Using XNOR convention (same used in earlier messages): feedback = not(xor(...))
    feedback_xnor <= not ( lfsr_q(39) xor lfsr_q(37) xor lfsr_q(20) xor lfsr_q(18) );

    ----------------------------------------------------------------------------
    -- synchronous process: reset / optional seed load / shift
    ----------------------------------------------------------------------------
    process(clk)
    begin
        if rising_edge(clk) then
            if rst = '1' then
                -- deterministic non-zero reset state (avoids 'U' and all-zero lock)
                lfsr_q <= DEFAULT_SEED;
            elsif load_seed = '1' then
                -- synchronous load; avoid all-zero seed
                if seed = x"00000000" then
                    lfsr_q <= DEFAULT_SEED;
                else
                    lfsr_q <= seed;
                end if;
            elsif enable = '1' then
                -- shift right: new MSB = feedback, LSB shifted out
                lfsr_q <= feedback_xnor & lfsr_q(39 downto 1);
            end if;
        end if;
    end process;

    ----------------------------------------------------------------------------
    -- output the state (MSB at index 39)
    ----------------------------------------------------------------------------
    lfsr_vec <= lfsr_q;

end architecture;


-- org_plpf_n2.vhd
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity org_plpf_n2 is
    port (
        clk       : in  std_logic;
        rst       : in  std_logic;
        valid     : in  std_logic;
        Tj        : in  std_logic;
        F1        : in  std_logic;
        out_valid : out std_logic;
        out_bit   : out std_logic
    );
end entity;

architecture rtl of org_plpf_n2 is
    signal prev_S    : std_logic := '0';
    signal or_all    : std_logic;
    signal and_all   : std_logic;
begin
    or_all  <= Tj or F1;
    and_all <= Tj and F1;

    proc_seq : process(clk)
        variable next_prev : std_logic;
    begin
        if rising_edge(clk) then
            if rst = '1' then
                prev_S    <= '0';
                out_valid <= '0';
                out_bit   <= '0';
            else
                if valid = '1' then
                    if prev_S = '1' then
                        out_bit <= or_all;
                        next_prev := or_all;
                    else
                        out_bit <= and_all;
                        next_prev := and_all;
                    end if;
                    out_valid <= '1';
                    prev_S <= next_prev;
                else
                    out_valid <= '0';
                end if;
            end if;
        end if;
    end process;
end architecture;
-- org_plpf_n3.vhd
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity org_plpf_n3 is
    port (
        clk       : in  std_logic;
        rst       : in  std_logic;
        valid     : in  std_logic;
        Tj        : in  std_logic;
        F1        : in  std_logic;
        F2        : in  std_logic;
        out_valid : out std_logic;
        out_bit   : out std_logic
    );
end entity;

architecture rtl of org_plpf_n3 is
    signal prev_S  : std_logic := '0';
    signal or_fut  : std_logic;
    signal and_fut : std_logic;
    signal or_all  : std_logic;
    signal and_all : std_logic;
begin
    -- compute reductions (combinational)
    proc_reduce : process(Tj, F1, F2)
    begin
        if (F1 = '1') or (F2 = '1') then
            or_fut <= '1';
        else
            or_fut <= '0';
        end if;

        if (F1 = '1') and (F2 = '1') then
            and_fut <= '1';
        else
            and_fut <= '0';
        end if;

        or_all  <= Tj or or_fut;
        and_all <= Tj and and_fut;
    end process;

    proc_seq : process(clk)
        variable next_prev : std_logic;
    begin
        if rising_edge(clk) then
            if rst = '1' then
                prev_S    <= '0';
                out_valid <= '0';
                out_bit   <= '0';
            else
                if valid = '1' then
                    if prev_S = '1' then
                        out_bit <= or_all;
                        next_prev := or_all;
                    else
                        out_bit <= and_all;
                        next_prev := and_all;
                    end if;
                    out_valid <= '1';
                    prev_S <= next_prev;
                else
                    out_valid <= '0';
                end if;
            end if;
        end if;
    end process;
end architecture;
-- dynamic_plpf_taps_40.vhd
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity dynamic_plpf_taps_40 is
    port (
        clk       : in  std_logic;
        rst       : in  std_logic;
        valid     : in  std_logic;
        lfsr_vec  : in  std_logic_vector(39 downto 0); -- 40-bit LFSR, MSB = Tj
        sel_n     : in  unsigned(1 downto 0);          -- "00"=n1, "01"=n2, "10"=n3
        out_valid : out std_logic;
        out_bit   : out std_logic
    );
end entity;

architecture rtl of dynamic_plpf_taps_40 is
    signal Tj : std_logic;
    signal F1 : std_logic;
    signal F2 : std_logic;

    signal p2_valid, p3_valid : std_logic;
    signal p2_bit, p3_bit     : std_logic;

    signal sel_int : integer range 1 to 3 := 1;
begin
    -- map taps: Tj = MSB (39), F1 = 38, F2 = 37
    Tj <= lfsr_vec(39);
    F1 <= lfsr_vec(38);
    F2 <= lfsr_vec(37);

    u_p2: entity work.org_plpf_n2
        port map (
            clk => clk, rst => rst, valid => valid,
            Tj => Tj, F1 => F1,
            out_valid => p2_valid, out_bit => p2_bit
        );

    u_p3: entity work.org_plpf_n3
        port map (
            clk => clk, rst => rst, valid => valid,
            Tj => Tj, F1 => F1, F2 => F2,
            out_valid => p3_valid, out_bit => p3_bit
        );

    -- decode sel
    decode_sel: process(sel_n)
    begin
        if sel_n = "00" then
            sel_int <= 1;
        elsif sel_n = "01" then
            sel_int <= 2;
        elsif sel_n = "10" then
            sel_int <= 3;
        else
            sel_int <= 1;
        end if;
    end process;

    -- synchronous mux (registered outputs)
    out_mux : process(clk)
    begin
        if rising_edge(clk) then
            if rst = '1' then
                out_valid <= '0';
                out_bit <= '0';
            else
                if sel_int = 1 then
                    if valid = '1' then
                        out_valid <= '1';
                        out_bit <= Tj;
                    else
                        out_valid <= '0';
                    end if;
                elsif sel_int = 2 then
                    out_valid <= p2_valid;
                    out_bit   <= p2_bit;
                else
                    out_valid <= p3_valid;
                    out_bit   <= p3_bit;
                end if;
            end if;
        end if;
    end process;
end architecture;

----------------------------------------------------------------------------------
-- MIPS32 5-stage pipeline with scan chains - CORRECTED VERSION
----------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

-- [All component entities remain the same: ALU, RegFile, InstrMem, DataMem, 
--  SignExt, ControlUnit, ALUControl, ForwardUnit, HazardUnit]
-- [Copying them from the original correct code...]

-- 1) ALU
entity ALU is
    port (
        A       : in  std_logic_vector(31 downto 0);
        B       : in  std_logic_vector(31 downto 0);
        ALUCtrl : in  std_logic_vector(3 downto 0);
        Result  : out std_logic_vector(31 downto 0);
        Zero    : out std_logic
    );
end ALU;

architecture Behavioral of ALU is
    constant ZERO32 : std_logic_vector(31 downto 0) := (others => '0');
begin
    process(A, B, ALUCtrl)
        variable tmp_v : std_logic_vector(31 downto 0);
        variable a_s   : signed(31 downto 0);
        variable b_s   : signed(31 downto 0);
        variable res_s : signed(31 downto 0);
    begin
        a_s := signed(A);
        b_s := signed(B);
        tmp_v := (others => '0');
        res_s := (others => '0');

        case ALUCtrl is
            when "0010" => res_s := a_s + b_s; tmp_v := std_logic_vector(res_s);
            when "0110" => res_s := a_s - b_s; tmp_v := std_logic_vector(res_s);
            when "0000" => tmp_v := A and B;
            when "0001" => tmp_v := A or B;
            when "0111" =>
                if a_s < b_s then
                    tmp_v := std_logic_vector(to_signed(1, 32));
                else
                    tmp_v := ZERO32;
                end if;
            when others => tmp_v := ZERO32;
        end case;

        Result <= tmp_v;
        if tmp_v = ZERO32 then
            Zero <= '1';
        else
            Zero <= '0';
        end if;
    end process;
end Behavioral;

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

-- 2) RegFile
entity RegFile is
    port (
        clk     : in  std_logic;
        we      : in  std_logic;
        rd_addr : in  std_logic_vector(4 downto 0);
        rs_addr : in  std_logic_vector(4 downto 0);
        rt_addr : in  std_logic_vector(4 downto 0);
        wd      : in  std_logic_vector(31 downto 0);
        rs_data : out std_logic_vector(31 downto 0);
        rt_data : out std_logic_vector(31 downto 0)
    );
end RegFile;

architecture Behavioral of RegFile is
    type reg_array is array(0 to 31) of std_logic_vector(31 downto 0);
    signal regs : reg_array := (others => (others => '0'));
begin
    rs_data <= regs(to_integer(unsigned(rs_addr)));
    rt_data <= regs(to_integer(unsigned(rt_addr)));

    process(clk)
    begin
        if rising_edge(clk) then
            if we = '1' then
                if rd_addr /= "00000" then
                    regs(to_integer(unsigned(rd_addr))) <= wd;
                end if;
            end if;
        end if;
    end process;
end Behavioral;

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

-- 3) InstrMem
entity InstrMem is
    port(
        Addr      : in  std_logic_vector(31 downto 0);
        Instr     : out std_logic_vector(31 downto 0);
        sim_we    : in  std_logic;
        sim_addr  : in  std_logic_vector(7 downto 0);
        sim_data  : in  std_logic_vector(31 downto 0)
    );
end InstrMem;

architecture Behavioral of InstrMem is
    type mem_type is array(0 to 255) of std_logic_vector(31 downto 0);
    signal ROM : mem_type := (others => (others => '0'));
begin
    Instr <= ROM(to_integer(unsigned(Addr(9 downto 2))));

    process(sim_we, sim_addr, sim_data)
    begin
        if sim_we = '1' then
            ROM(to_integer(unsigned(sim_addr))) <= sim_data;
        end if;
    end process;
end Behavioral;

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

-- 4) DataMem
entity DataMem is
    port (
        clk        : in  std_logic;
        mem_write  : in  std_logic;
        mem_read   : in  std_logic;
        Addr       : in  std_logic_vector(31 downto 0);
        WriteData  : in  std_logic_vector(31 downto 0);
        ReadData   : out std_logic_vector(31 downto 0)
    );
end DataMem;

architecture Behavioral of DataMem is
    type ram_type is array(0 to 1023) of std_logic_vector(31 downto 0);
    signal RAM : ram_type := (others => (others => '0'));
    signal rdata_reg : std_logic_vector(31 downto 0) := (others => '0');
begin
    process(clk)
    begin
        if rising_edge(clk) then
            if mem_write = '1' then
                RAM(to_integer(unsigned(Addr(11 downto 2)))) <= WriteData;
            end if;
            if mem_read = '1' then
                rdata_reg <= RAM(to_integer(unsigned(Addr(11 downto 2))));
            end if;
        end if;
    end process;
    ReadData <= rdata_reg;
end Behavioral;

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

-- 5) SignExt
entity SignExt is
    port (
        Imm16 : in  std_logic_vector(15 downto 0);
        Imm32 : out std_logic_vector(31 downto 0)
    );
end SignExt;

architecture Behavioral of SignExt is
begin
    Imm32 <= std_logic_vector(resize(signed(Imm16), 32));
end Behavioral;

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

-- 6) ControlUnit
entity ControlUnit is
    port (
        Opcode     : in  std_logic_vector(5 downto 0);
        RegDst     : out std_logic;
        ALUSrc     : out std_logic;
        MemToReg   : out std_logic;
        RegWrite   : out std_logic;
        MemRead    : out std_logic;
        MemWrite   : out std_logic;
        Branch     : out std_logic;
        Jump       : out std_logic;
        ALUOp      : out std_logic_vector(1 downto 0)
    );
end ControlUnit;

architecture Behavioral of ControlUnit is
begin
    process(Opcode)
    begin
        RegDst   <= '0'; ALUSrc   <= '0'; MemToReg <= '0'; RegWrite <= '0';
        MemRead  <= '0'; MemWrite <= '0'; Branch   <= '0'; Jump     <= '0';
        ALUOp    <= "00";
        case Opcode is
            when "000000" => RegDst <= '1'; RegWrite <= '1'; ALUOp <= "10";
            when "100011" => ALUSrc <= '1'; MemToReg <= '1'; RegWrite <= '1'; MemRead <= '1';
            when "101011" => ALUSrc <= '1'; MemWrite <= '1';
            when "000100" => Branch <= '1'; ALUOp <= "01";
            when "001000" => ALUSrc <= '1'; RegWrite <= '1';
            when "000010" => Jump <= '1';
            when others => null;
        end case;
    end process;
end Behavioral;

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

-- 7) ALUControl
entity ALUControl is
    port (
        ALUOp    : in  std_logic_vector(1 downto 0);
        Funct    : in  std_logic_vector(5 downto 0);
        ALUCtrl  : out std_logic_vector(3 downto 0)
    );
end ALUControl;

architecture Behavioral of ALUControl is
begin
    process(ALUOp, Funct)
    begin
        if ALUOp = "00" then
            ALUCtrl <= "0010";
        elsif ALUOp = "01" then
            ALUCtrl <= "0110";
        else
            case Funct is
                when "100000" => ALUCtrl <= "0010";
                when "100010" => ALUCtrl <= "0110";
                when "100100" => ALUCtrl <= "0000";
                when "100101" => ALUCtrl <= "0001";
                when "101010" => ALUCtrl <= "0111";
                when others   => ALUCtrl <= "0010";
            end case;
        end if;
    end process;
end Behavioral;

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

-- 8) ForwardUnit
entity ForwardUnit is
    port (
        EX_MEM_RegWrite : in std_logic;
        MEM_WB_RegWrite : in std_logic;
        EX_MEM_Rd       : in std_logic_vector(4 downto 0);
        MEM_WB_Rd       : in std_logic_vector(4 downto 0);
        ID_EX_Rs        : in std_logic_vector(4 downto 0);
        ID_EX_Rt        : in std_logic_vector(4 downto 0);
        ForwardA        : out std_logic_vector(1 downto 0);
        ForwardB        : out std_logic_vector(1 downto 0)
    );
end ForwardUnit;

architecture Behavioral of ForwardUnit is
begin
    process(EX_MEM_RegWrite, MEM_WB_RegWrite, EX_MEM_Rd, MEM_WB_Rd, ID_EX_Rs, ID_EX_Rt)
    begin
        ForwardA <= "00"; ForwardB <= "00";
        if (EX_MEM_RegWrite = '1') and (EX_MEM_Rd /= "00000") and (EX_MEM_Rd = ID_EX_Rs) then
            ForwardA <= "10";
        end if;
        if (EX_MEM_RegWrite = '1') and (EX_MEM_Rd /= "00000") and (EX_MEM_Rd = ID_EX_Rt) then
            ForwardB <= "10";
        end if;
        if (MEM_WB_RegWrite = '1') and (MEM_WB_Rd /= "00000") and 
           (not ((EX_MEM_RegWrite = '1') and (EX_MEM_Rd /= "00000") and (EX_MEM_Rd = ID_EX_Rs))) and 
           (MEM_WB_Rd = ID_EX_Rs) then
            ForwardA <= "01";
        end if;
        if (MEM_WB_RegWrite = '1') and (MEM_WB_Rd /= "00000") and 
           (not ((EX_MEM_RegWrite = '1') and (EX_MEM_Rd /= "00000") and (EX_MEM_Rd = ID_EX_Rt))) and 
           (MEM_WB_Rd = ID_EX_Rt) then
            ForwardB <= "01";
        end if;
    end process;
end Behavioral;

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

-- 9) HazardUnit
entity HazardUnit is
    port (
        ID_EX_MemRead : in std_logic;
        ID_EX_Rt      : in std_logic_vector(4 downto 0);
        IF_ID_Rs      : in std_logic_vector(4 downto 0);
        IF_ID_Rt      : in std_logic_vector(4 downto 0);
        PCWrite       : out std_logic;
        IF_ID_Write   : out std_logic;
        Stall         : out std_logic
    );
end HazardUnit;

architecture Behavioral of HazardUnit is
begin
    process(ID_EX_MemRead, ID_EX_Rt, IF_ID_Rs, IF_ID_Rt)
    begin
        if (ID_EX_MemRead = '1') and ((ID_EX_Rt = IF_ID_Rs) or (ID_EX_Rt = IF_ID_Rt)) then
            PCWrite <= '0'; IF_ID_Write <= '0'; Stall <= '1';
        else
            PCWrite <= '1'; IF_ID_Write <= '1'; Stall <= '0';
        end if;
    end process;
end Behavioral;

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;


library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

-- 10) MIPS5Pipe top with PLPF-driven scan chain inputs and top-level MISR outputs
entity MIPS5Pipe is
    port(
        clk   : in std_logic;
        reset : in std_logic;
        sim_we    : in std_logic := '0';
        sim_addr  : in std_logic_vector(7 downto 0) := (others=>'0');
        sim_data  : in std_logic_vector(31 downto 0) := (others=>'0');

        debug_PC         : out std_logic_vector(31 downto 0);
        debug_Instr      : out std_logic_vector(31 downto 0);
        debug_ALUResult  : out std_logic_vector(31 downto 0);
        debug_Zero       : out std_logic;
        debug_ALUCtrl    : out std_logic_vector(3 downto 0);
        debug_ALU_InA    : out std_logic_vector(31 downto 0);
        debug_ALU_InB    : out std_logic_vector(31 downto 0);
        debug_SignExtImm : out std_logic_vector(31 downto 0);
        debug_RegWrite   : out std_logic;

        -- scan control (external enables kept)
        scan_en_pc      : in  std_logic := '0';
        scan_in_pc      : in  std_logic := '0'; -- kept in port list for compatibility, but not used
        scan_out_pc     : out std_logic;
        scan_en_ifid    : in  std_logic := '0';
        scan_in_ifid    : in  std_logic := '0'; -- kept but unused
        scan_out_ifid   : out std_logic;
        scan_en_idex    : in  std_logic := '0';
        scan_in_idex    : in  std_logic := '0'; -- kept but unused
        scan_out_idex   : out std_logic;
        scan_en_exmem   : in  std_logic := '0';
        scan_in_exmem    : in  std_logic := '0'; -- kept but unused
        scan_out_exmem  : out std_logic;
        scan_en_memwb   : in  std_logic := '0';
        scan_in_memwb   : in  std_logic := '0'; -- kept but unused
        scan_out_memwb  : out std_logic;

        -- TOP-LEVEL MISR OUTPUTS (signatures)
        misr_pc_sig    : out std_logic_vector(31 downto 0);
        misr_ifid_sig  : out std_logic_vector(63 downto 0);
        misr_idex_sig  : out std_logic_vector(151 downto 0);
        misr_exmem_sig : out std_logic_vector(74 downto 0);
        misr_memwb_sig : out std_logic_vector(70 downto 0)
    );
end MIPS5Pipe;

architecture Behavioral of MIPS5Pipe is
    -- Functional registers
    signal reg_PC : std_logic_vector(31 downto 0) := (others => '0');
    signal reg_IF_ID_PC    : std_logic_vector(31 downto 0) := (others => '0');
    signal reg_IF_ID_Instr : std_logic_vector(31 downto 0) := (others => '0');
    
    signal reg_ID_EX_RegDst, reg_ID_EX_ALUSrc, reg_ID_EX_MemToReg, reg_ID_EX_RegWrite,
           reg_ID_EX_MemRead, reg_ID_EX_MemWrite, reg_ID_EX_Branch : std_logic := '0';
    signal reg_ID_EX_ALUOp : std_logic_vector(1 downto 0) := (others => '0');
    signal reg_ID_EX_PC, reg_ID_EX_RSdata, reg_ID_EX_RTdata, reg_ID_EX_Imm32 : std_logic_vector(31 downto 0) := (others => '0');
    signal reg_ID_EX_Rs, reg_ID_EX_Rt, reg_ID_EX_Rd : std_logic_vector(4 downto 0) := (others => '0');

    signal reg_EX_MEM_MemToReg, reg_EX_MEM_RegWrite, reg_EX_MEM_MemRead, reg_EX_MEM_MemWrite, reg_EX_MEM_Branch : std_logic := '0';
    signal reg_EX_MEM_ALUResult, reg_EX_MEM_RTdata : std_logic_vector(31 downto 0) := (others => '0');
    signal reg_EX_MEM_WriteReg : std_logic_vector(4 downto 0) := (others => '0');
    signal reg_EX_MEM_Zero : std_logic := '0';

    signal reg_MEM_WB_MemToReg, reg_MEM_WB_RegWrite : std_logic := '0';
    signal reg_MEM_WB_ReadData, reg_MEM_WB_ALUResult : std_logic_vector(31 downto 0) := (others => '0');
    signal reg_MEM_WB_WriteReg : std_logic_vector(4 downto 0) := (others => '0');

    -- Pipe signals
    signal PC, PC_next, Instr_IF : std_logic_vector(31 downto 0);
    signal IF_ID_PC, IF_ID_Instr : std_logic_vector(31 downto 0);
    
    signal ID_EX_RegDst, ID_EX_ALUSrc, ID_EX_MemToReg, ID_EX_RegWrite, ID_EX_MemRead, ID_EX_MemWrite, ID_EX_Branch : std_logic;
    signal ID_EX_ALUOp  : std_logic_vector(1 downto 0);
    signal ID_EX_PC, ID_EX_RSdata, ID_EX_RTdata, ID_EX_Imm32 : std_logic_vector(31 downto 0);
    signal ID_EX_Rs, ID_EX_Rt, ID_EX_Rd : std_logic_vector(4 downto 0);

    signal EX_MEM_MemToReg, EX_MEM_RegWrite, EX_MEM_MemRead, EX_MEM_MemWrite, EX_MEM_Branch : std_logic;
    signal EX_MEM_ALUResult, EX_MEM_RTdata : std_logic_vector(31 downto 0);
    signal EX_MEM_WriteReg : std_logic_vector(4 downto 0);
    signal EX_MEM_Zero : std_logic;

    signal MEM_WB_MemToReg, MEM_WB_RegWrite : std_logic;
    signal MEM_WB_ReadData, MEM_WB_ALUResult : std_logic_vector(31 downto 0);
    signal MEM_WB_WriteReg : std_logic_vector(4 downto 0);

    signal RegDst_i, ALUSrc_i, MemToReg_i, RegWrite_i, MemRead_i, MemWrite_i, Branch_i, Jump_i : std_logic;
    signal ALUOp_i : std_logic_vector(1 downto 0);
    signal RS_data, RT_data, Imm32 : std_logic_vector(31 downto 0);
    signal ALU_input_B, ALUResult_ex : std_logic_vector(31 downto 0);
    signal ALUZero_ex : std_logic;
    signal ALUCtrl_ex : std_logic_vector(3 downto 0);
    signal rs_value_for_alu, rt_value_for_alu : std_logic_vector(31 downto 0);
    signal EX_WriteReg : std_logic_vector(4 downto 0);
    signal MEM_ReadData, WB_WriteData : std_logic_vector(31 downto 0);
    signal ForwardA, ForwardB : std_logic_vector(1 downto 0);
    signal PCWrite, IF_ID_Write, Stall : std_logic;

    -- Scan chain constants
    constant W_PC    : integer := 32;
    constant W_IFID  : integer := 64;
    constant W_IDEX  : integer := 152;
    constant W_EXMEM : integer := 75;
    constant W_MEMWB : integer := 71;

    signal scan_chain_pc    : std_logic_vector(W_PC-1 downto 0) := (others => '0');
    signal scan_chain_ifid  : std_logic_vector(W_IFID-1 downto 0) := (others => '0');
    signal scan_chain_idex  : std_logic_vector(W_IDEX-1 downto 0) := (others => '0');
    signal scan_chain_exmem : std_logic_vector(W_EXMEM-1 downto 0) := (others => '0');
    signal scan_chain_memwb : std_logic_vector(W_MEMWB-1 downto 0) := (others => '0');

    signal func_pc_concat    : std_logic_vector(W_PC-1 downto 0);
    signal func_ifid_concat  : std_logic_vector(W_IFID-1 downto 0);
    signal func_idex_concat  : std_logic_vector(W_IDEX-1 downto 0);
    signal func_exmem_concat : std_logic_vector(W_EXMEM-1 downto 0);
    signal func_memwb_concat : std_logic_vector(W_MEMWB-1 downto 0);

    -- PLPF / LFSR signals (drive scan_in bits from PLPF outputs)
    signal lfsr_vec_sig : std_logic_vector(39 downto 0);
    signal plpf_pc_bit  : std_logic := '0';
    signal plpf_ifid_bit: std_logic := '0';
    signal plpf_idex_bit: std_logic := '0';
    signal plpf_exmem_bit: std_logic := '0';

    -- Internal MISR signature signals (renamed to avoid port-name clash)
    signal misr_pc_sig_int    : std_logic_vector(W_PC-1 downto 0) := (others => '0');
    signal misr_ifid_sig_int  : std_logic_vector(W_IFID-1 downto 0) := (others => '0');
    signal misr_idex_sig_int  : std_logic_vector(W_IDEX-1 downto 0) := (others => '0');
    signal misr_exmem_sig_int : std_logic_vector(W_EXMEM-1 downto 0) := (others => '0');
    signal misr_memwb_sig_int : std_logic_vector(W_MEMWB-1 downto 0) := (others => '0');

begin
    -- Component instantiations (functional units unchanged)
    InstrMem_inst : entity work.InstrMem
        port map(Addr => PC, Instr => Instr_IF, sim_we => sim_we, sim_addr => sim_addr, sim_data => sim_data);

    RegFile_inst : entity work.RegFile
        port map(clk => clk, we => MEM_WB_RegWrite, rd_addr => MEM_WB_WriteReg,
                 rs_addr => IF_ID_Instr(25 downto 21), rt_addr => IF_ID_Instr(20 downto 16),
                 wd => WB_WriteData, rs_data => RS_data, rt_data => RT_data);

    Control_inst : entity work.ControlUnit
        port map(Opcode => IF_ID_Instr(31 downto 26), RegDst => RegDst_i, ALUSrc => ALUSrc_i,
                 MemToReg => MemToReg_i, RegWrite => RegWrite_i, MemRead => MemRead_i,
                 MemWrite => MemWrite_i, Branch => Branch_i, Jump => Jump_i, ALUOp => ALUOp_i);

    SignExt_inst : entity work.SignExt
        port map(Imm16 => IF_ID_Instr(15 downto 0), Imm32 => Imm32);

    ALUControl_inst : entity work.ALUControl
        port map(ALUOp => ID_EX_ALUOp, Funct => ID_EX_Imm32(5 downto 0), ALUCtrl => ALUCtrl_ex);

    ALU_inst : entity work.ALU
        port map(A => rs_value_for_alu, B => ALU_input_B, ALUCtrl => ALUCtrl_ex,
                 Result => ALUResult_ex, Zero => ALUZero_ex);

    Forward_inst : entity work.ForwardUnit
        port map(EX_MEM_RegWrite => EX_MEM_RegWrite, MEM_WB_RegWrite => MEM_WB_RegWrite,
                 EX_MEM_Rd => EX_MEM_WriteReg, MEM_WB_Rd => MEM_WB_WriteReg,
                 ID_EX_Rs => ID_EX_Rs, ID_EX_Rt => ID_EX_Rt,
                 ForwardA => ForwardA, ForwardB => ForwardB);

    Hazard_inst : entity work.HazardUnit
        port map(ID_EX_MemRead => ID_EX_MemRead, ID_EX_Rt => ID_EX_Rt,
                 IF_ID_Rs => IF_ID_Instr(25 downto 21), IF_ID_Rt => IF_ID_Instr(20 downto 16),
                 PCWrite => PCWrite, IF_ID_Write => IF_ID_Write, Stall => Stall);

    DataMem_inst : entity work.DataMem
        port map(clk => clk, mem_write => EX_MEM_MemWrite, mem_read => EX_MEM_MemRead,
                 Addr => EX_MEM_ALUResult, WriteData => EX_MEM_RTdata, ReadData => MEM_ReadData);

    -- LFSR and PLPF instantiations (drive scan-chain serial input bits)
    u_lfsr40: entity work.lfsr40
        port map(
            clk => clk,
            rst => reset,
            load_seed => '0',
            seed => (others => '0'),
            enable => '1',
            lfsr_vec => lfsr_vec_sig
        );

    -- One dynamic PLPF per scan chain. valid tied to scan_en signals.
    u_plpf_pc: entity work.dynamic_plpf_taps_40
        port map(
            clk => clk, rst => reset, valid => scan_en_pc,
            lfsr_vec => lfsr_vec_sig, sel_n => "00",
            out_valid => open, out_bit => plpf_pc_bit
        );

    u_plpf_ifid: entity work.dynamic_plpf_taps_40
        port map(
            clk => clk, rst => reset, valid => scan_en_ifid,
            lfsr_vec => lfsr_vec_sig, sel_n => "01",
            out_valid => open, out_bit => plpf_ifid_bit
        );

    u_plpf_idex: entity work.dynamic_plpf_taps_40
        port map(
            clk => clk, rst => reset, valid => scan_en_idex,
            lfsr_vec => lfsr_vec_sig, sel_n => "10",
            out_valid => open, out_bit => plpf_idex_bit
        );

    u_plpf_exmem: entity work.dynamic_plpf_taps_40
        port map(
            clk => clk, rst => reset, valid => scan_en_exmem,
            lfsr_vec => lfsr_vec_sig, sel_n => "00",
            out_valid => open, out_bit => plpf_exmem_bit
        );

    -- Functional concatenations
    func_pc_concat <= reg_PC;
    func_ifid_concat <= reg_IF_ID_PC & reg_IF_ID_Instr;
    func_idex_concat <= (reg_ID_EX_RegDst & reg_ID_EX_ALUSrc & reg_ID_EX_MemToReg & reg_ID_EX_RegWrite &
                         reg_ID_EX_MemRead & reg_ID_EX_MemWrite & reg_ID_EX_Branch & reg_ID_EX_ALUOp) &
                        reg_ID_EX_PC & reg_ID_EX_RSdata & reg_ID_EX_RTdata & reg_ID_EX_Imm32 &
                        reg_ID_EX_Rs & reg_ID_EX_Rt & reg_ID_EX_Rd;
    func_exmem_concat <= (reg_EX_MEM_MemToReg & reg_EX_MEM_RegWrite & reg_EX_MEM_MemRead & 
                          reg_EX_MEM_MemWrite & reg_EX_MEM_Branch) &
                         reg_EX_MEM_ALUResult & reg_EX_MEM_RTdata & reg_EX_MEM_WriteReg & reg_EX_MEM_Zero;
    func_memwb_concat <= (reg_MEM_WB_MemToReg & reg_MEM_WB_RegWrite) &
                         reg_MEM_WB_ReadData & reg_MEM_WB_ALUResult & reg_MEM_WB_WriteReg;

    -- Scan chain processes: use PLPF outputs as the serial input when shifting.
    process(clk, reset)
    begin
        if reset = '1' then
            scan_chain_pc <= (others => '0');
        elsif rising_edge(clk) then
            if scan_en_pc = '1' then
                scan_chain_pc <= plpf_pc_bit & scan_chain_pc(W_PC-1 downto 1);
            else
                scan_chain_pc <= func_pc_concat;
            end if;
        end if;
    end process;
    scan_out_pc <= scan_chain_pc(0);

    process(clk, reset)
    begin
        if reset = '1' then
            scan_chain_ifid <= (others => '0');
        elsif rising_edge(clk) then
            if scan_en_ifid = '1' then
                scan_chain_ifid <= plpf_ifid_bit & scan_chain_ifid(W_IFID-1 downto 1);
            else
                scan_chain_ifid <= func_ifid_concat;
            end if;
        end if;
    end process;
    scan_out_ifid <= scan_chain_ifid(0);

    process(clk, reset)
    begin
        if reset = '1' then
            scan_chain_idex <= (others => '0');
        elsif rising_edge(clk) then
            if scan_en_idex = '1' then
                scan_chain_idex <= plpf_idex_bit & scan_chain_idex(W_IDEX-1 downto 1);
            else
                scan_chain_idex <= func_idex_concat;
            end if;
        end if;
    end process;
    scan_out_idex <= scan_chain_idex(0);

    process(clk, reset)
    begin
        if reset = '1' then
            scan_chain_exmem <= (others => '0');
        elsif rising_edge(clk) then
            if scan_en_exmem = '1' then
                scan_chain_exmem <= plpf_exmem_bit & scan_chain_exmem(W_EXMEM-1 downto 1);
            else
                scan_chain_exmem <= func_exmem_concat;
            end if;
        end if;
    end process;
    scan_out_exmem <= scan_chain_exmem(0);

    process(clk, reset)
    begin
        if reset = '1' then
            scan_chain_memwb <= (others => '0');
        elsif rising_edge(clk) then
            if scan_en_memwb = '1' then
                scan_chain_memwb <= scan_in_memwb & scan_chain_memwb(W_MEMWB-1 downto 1);
            else
                scan_chain_memwb <= func_memwb_concat;
            end if;
        end if;
    end process;
    scan_out_memwb <= scan_chain_memwb(0);

    ----------------------------------------------------------------
    -- MISR instantiations (placed AFTER scan chains so 'scan_chain_*' is valid)
    -- MISRs are disabled while the chain is shifting (enable = not scan_en_*)
    ----------------------------------------------------------------
    u_misr_pc: entity work.MISR
        generic map ( W => W_PC )
        port map (
            clk     => clk,
            rst     => reset,
            enable  => not scan_en_pc,        -- MISR off while loading
            din     => scan_chain_pc,
            sig_out => misr_pc_sig_int
        );

    u_misr_ifid: entity work.MISR
        generic map ( W => W_IFID )
        port map (
            clk     => clk,
            rst     => reset,
            enable  => not scan_en_ifid,
            din     => scan_chain_ifid,
            sig_out => misr_ifid_sig_int
        );

    u_misr_idex: entity work.MISR
        generic map ( W => W_IDEX )
        port map (
            clk     => clk,
            rst     => reset,
            enable  => not scan_en_idex,
            din     => scan_chain_idex,
            sig_out => misr_idex_sig_int
        );

    u_misr_exmem: entity work.MISR
        generic map ( W => W_EXMEM )
        port map (
            clk     => clk,
            rst     => reset,
            enable  => not scan_en_exmem,
            din     => scan_chain_exmem,
            sig_out => misr_exmem_sig_int
        );

    u_misr_memwb: entity work.MISR
        generic map ( W => W_MEMWB )
        port map (
            clk     => clk,
            rst     => reset,
            enable  => not scan_en_memwb,
            din     => scan_chain_memwb,
            sig_out => misr_memwb_sig_int
        );

    -- connect internal MISR signals to entity outputs
    misr_pc_sig    <= misr_pc_sig_int;
    misr_ifid_sig  <= misr_ifid_sig_int;
    misr_idex_sig  <= misr_idex_sig_int;
    misr_exmem_sig <= misr_exmem_sig_int;
    misr_memwb_sig <= misr_memwb_sig_int;

    -- Pipe signal selection from scan chains or functional registers
    PC <= scan_chain_pc when scan_en_pc = '1' else reg_PC;

    IF_ID_PC    <= scan_chain_ifid(W_IFID-1 downto 32) when scan_en_ifid = '1' else reg_IF_ID_PC;
    IF_ID_Instr <= scan_chain_ifid(31 downto 0)        when scan_en_ifid = '1' else reg_IF_ID_Instr;

    ID_EX_RegDst   <= scan_chain_idex(151) when scan_en_idex = '1' else reg_ID_EX_RegDst;
    ID_EX_ALUSrc   <= scan_chain_idex(150) when scan_en_idex = '1' else reg_ID_EX_ALUSrc;
    ID_EX_MemToReg <= scan_chain_idex(149) when scan_en_idex = '1' else reg_ID_EX_MemToReg;
    ID_EX_RegWrite <= scan_chain_idex(148) when scan_en_idex = '1' else reg_ID_EX_RegWrite;
    ID_EX_MemRead  <= scan_chain_idex(147) when scan_en_idex = '1' else reg_ID_EX_MemRead;
    ID_EX_MemWrite <= scan_chain_idex(146) when scan_en_idex = '1' else reg_ID_EX_MemWrite;
    ID_EX_Branch   <= scan_chain_idex(145) when scan_en_idex = '1' else reg_ID_EX_Branch;
    ID_EX_ALUOp    <= scan_chain_idex(144 downto 143) when scan_en_idex = '1' else reg_ID_EX_ALUOp;
    ID_EX_PC       <= scan_chain_idex(142 downto 111) when scan_en_idex = '1' else reg_ID_EX_PC;
    ID_EX_RSdata   <= scan_chain_idex(110 downto 79)  when scan_en_idex = '1' else reg_ID_EX_RSdata;
    ID_EX_RTdata   <= scan_chain_idex(78 downto 47)   when scan_en_idex = '1' else reg_ID_EX_RTdata;
    ID_EX_Imm32    <= scan_chain_idex(46 downto 15)   when scan_en_idex = '1' else reg_ID_EX_Imm32;
    ID_EX_Rs       <= scan_chain_idex(14 downto 10)   when scan_en_idex = '1' else reg_ID_EX_Rs;
    ID_EX_Rt       <= scan_chain_idex(9 downto 5)     when scan_en_idex = '1' else reg_ID_EX_Rt;
    ID_EX_Rd       <= scan_chain_idex(4 downto 0)     when scan_en_idex = '1' else reg_ID_EX_Rd;

    EX_MEM_MemToReg <= scan_chain_exmem(74) when scan_en_exmem = '1' else reg_EX_MEM_MemToReg;
    EX_MEM_RegWrite <= scan_chain_exmem(73) when scan_en_exmem = '1' else reg_EX_MEM_RegWrite;
    EX_MEM_MemRead  <= scan_chain_exmem(72) when scan_en_exmem = '1' else reg_EX_MEM_MemRead;
    EX_MEM_MemWrite <= scan_chain_exmem(71) when scan_en_exmem = '1' else reg_EX_MEM_MemWrite;
    EX_MEM_Branch   <= scan_chain_exmem(70) when scan_en_exmem = '1' else reg_EX_MEM_Branch;
    EX_MEM_ALUResult <= scan_chain_exmem(69 downto 38) when scan_en_exmem = '1' else reg_EX_MEM_ALUResult;
    EX_MEM_RTdata    <= scan_chain_exmem(37 downto 6)  when scan_en_exmem = '1' else reg_EX_MEM_RTdata;
    EX_MEM_WriteReg  <= scan_chain_exmem(5 downto 1)   when scan_en_exmem = '1' else reg_EX_MEM_WriteReg;
    EX_MEM_Zero      <= scan_chain_exmem(0)            when scan_en_exmem = '1' else reg_EX_MEM_Zero;

    MEM_WB_MemToReg  <= scan_chain_memwb(70) when scan_en_memwb = '1' else reg_MEM_WB_MemToReg;
    MEM_WB_RegWrite  <= scan_chain_memwb(69) when scan_en_memwb = '1' else reg_MEM_WB_RegWrite;
    MEM_WB_ReadData  <= scan_chain_memwb(68 downto 37) when scan_en_memwb = '1' else reg_MEM_WB_ReadData;
    MEM_WB_ALUResult <= scan_chain_memwb(36 downto 5)  when scan_en_memwb = '1' else reg_MEM_WB_ALUResult;
    MEM_WB_WriteReg  <= scan_chain_memwb(4 downto 0)   when scan_en_memwb = '1' else reg_MEM_WB_WriteReg;

    -- Functional register update processes (unchanged) ...
    process(clk, reset)
    begin
        if reset = '1' then
            reg_PC <= (others => '0');
        elsif rising_edge(clk) then
            if PCWrite = '1' then
                reg_PC <= PC_next;
            end if;
        end if;
    end process;

    process(clk, reset)
    begin
        if reset = '1' then
            reg_IF_ID_PC <= (others => '0');
            reg_IF_ID_Instr <= (others => '0');
        elsif rising_edge(clk) then
            if IF_ID_Write = '1' then
                reg_IF_ID_PC <= PC;
                reg_IF_ID_Instr <= Instr_IF;
            end if;
        end if;
    end process;

    process(clk, reset)
    begin
        if reset = '1' then
            reg_ID_EX_RegDst <= '0';
            reg_ID_EX_ALUSrc <= '0';
            reg_ID_EX_MemToReg <= '0';
            reg_ID_EX_RegWrite <= '0';
            reg_ID_EX_MemRead <= '0';
            reg_ID_EX_MemWrite <= '0';
            reg_ID_EX_Branch <= '0';
            reg_ID_EX_ALUOp <= (others => '0');
            reg_ID_EX_PC <= (others => '0');
            reg_ID_EX_RSdata <= (others => '0');
            reg_ID_EX_RTdata <= (others => '0');
            reg_ID_EX_Imm32 <= (others => '0');
            reg_ID_EX_Rs <= (others => '0');
            reg_ID_EX_Rt <= (others => '0');
            reg_ID_EX_Rd <= (others => '0');
        elsif rising_edge(clk) then
            if Stall = '1' then
                reg_ID_EX_RegDst <= '0';
                reg_ID_EX_ALUSrc <= '0';
                reg_ID_EX_MemToReg <= '0';
                reg_ID_EX_RegWrite <= '0';
                reg_ID_EX_MemRead <= '0';
                reg_ID_EX_MemWrite <= '0';
                reg_ID_EX_Branch <= '0';
                reg_ID_EX_ALUOp <= (others => '0');
            else
                reg_ID_EX_RegDst <= RegDst_i;
                reg_ID_EX_ALUSrc <= ALUSrc_i;
                reg_ID_EX_MemToReg <= MemToReg_i;
                reg_ID_EX_RegWrite <= RegWrite_i;
                reg_ID_EX_MemRead <= MemRead_i;
                reg_ID_EX_MemWrite <= MemWrite_i;
                reg_ID_EX_Branch <= Branch_i;
                reg_ID_EX_ALUOp <= ALUOp_i;
                reg_ID_EX_PC <= IF_ID_PC;
                reg_ID_EX_RSdata <= RS_data;
                reg_ID_EX_RTdata <= RT_data;
                reg_ID_EX_Imm32 <= Imm32;
                reg_ID_EX_Rs <= IF_ID_Instr(25 downto 21);
                reg_ID_EX_Rt <= IF_ID_Instr(20 downto 16);
                reg_ID_EX_Rd <= IF_ID_Instr(15 downto 11);
            end if;
        end if;
    end process;

    process(clk, reset)
    begin
        if reset = '1' then
            reg_EX_MEM_MemToReg <= '0';
            reg_EX_MEM_RegWrite <= '0';
            reg_EX_MEM_MemRead <= '0';
            reg_EX_MEM_MemWrite <= '0';
            reg_EX_MEM_Branch <= '0';
            reg_EX_MEM_ALUResult <= (others => '0');
            reg_EX_MEM_RTdata <= (others => '0');
            reg_EX_MEM_WriteReg <= (others => '0');
            reg_EX_MEM_Zero <= '0';
        elsif rising_edge(clk) then
            reg_EX_MEM_MemToReg <= ID_EX_MemToReg;
            reg_EX_MEM_RegWrite <= ID_EX_RegWrite;
            reg_EX_MEM_MemRead <= ID_EX_MemRead;
            reg_EX_MEM_MemWrite <= ID_EX_MemWrite;
            reg_EX_MEM_Branch <= ID_EX_Branch;
            reg_EX_MEM_ALUResult <= ALUResult_ex;
            reg_EX_MEM_RTdata <= rt_value_for_alu;
            reg_EX_MEM_WriteReg <= EX_WriteReg;
            reg_EX_MEM_Zero <= ALUZero_ex;
        end if;
    end process;

    process(clk, reset)
    begin
        if reset = '1' then
            reg_MEM_WB_MemToReg <= '0';
            reg_MEM_WB_RegWrite <= '0';
            reg_MEM_WB_ReadData <= (others => '0');
            reg_MEM_WB_ALUResult <= (others => '0');
            reg_MEM_WB_WriteReg <= (others => '0');
        elsif rising_edge(clk) then
            reg_MEM_WB_MemToReg <= EX_MEM_MemToReg;
            reg_MEM_WB_RegWrite <= EX_MEM_RegWrite;
            reg_MEM_WB_ReadData <= MEM_ReadData;
            reg_MEM_WB_ALUResult <= EX_MEM_ALUResult;
            reg_MEM_WB_WriteReg <= EX_MEM_WriteReg;
        end if;
    end process;

    -- Datapath logic and remaining code unchanged...
    WB_WriteData <= MEM_WB_ReadData when MEM_WB_MemToReg = '1' else MEM_WB_ALUResult;

    process(PC, EX_MEM_Branch, EX_MEM_Zero, IF_ID_Instr, Jump_i, EX_MEM_ALUResult)
        variable pc_plus4 : std_logic_vector(31 downto 0);
        variable jump_target : std_logic_vector(31 downto 0);
    begin
        pc_plus4 := std_logic_vector(unsigned(PC) + 4);
        jump_target := (pc_plus4(31 downto 28) & IF_ID_Instr(25 downto 0) & "00");
        PC_next <= pc_plus4;
        if (EX_MEM_Branch = '1') and (EX_MEM_Zero = '1') then
            PC_next <= EX_MEM_ALUResult;
        elsif Jump_i = '1' then
            PC_next <= jump_target;
        end if;
    end process;

    -- Forwarding muxes, ALU input selection, EX dest compute, debug outputs...
    process(ForwardA, ID_EX_RSdata, EX_MEM_ALUResult, MEM_WB_ALUResult, MEM_WB_ReadData, MEM_WB_MemToReg)
    begin
        case ForwardA is
            when "00" => rs_value_for_alu <= ID_EX_RSdata;
            when "10" => rs_value_for_alu <= EX_MEM_ALUResult;
            when "01" =>
                if MEM_WB_MemToReg = '1' then
                    rs_value_for_alu <= MEM_WB_ReadData;
                else
                    rs_value_for_alu <= MEM_WB_ALUResult;
                end if;
            when others => rs_value_for_alu <= ID_EX_RSdata;
        end case;
    end process;

    process(ForwardB, ID_EX_RTdata, EX_MEM_ALUResult, MEM_WB_ALUResult, MEM_WB_ReadData, MEM_WB_MemToReg)
    begin
        case ForwardB is
            when "00" => rt_value_for_alu <= ID_EX_RTdata;
            when "10" => rt_value_for_alu <= EX_MEM_ALUResult;
            when "01" =>
                if MEM_WB_MemToReg = '1' then
                    rt_value_for_alu <= MEM_WB_ReadData;
                else
                    rt_value_for_alu <= MEM_WB_ALUResult;
                end if;
            when others => rt_value_for_alu <= ID_EX_RTdata;
        end case;
    end process;

    ALU_input_B <= ID_EX_Imm32 when ID_EX_ALUSrc = '1' else rt_value_for_alu;

    process(ID_EX_RegDst, ID_EX_Rt, ID_EX_Rd)
    begin
        if ID_EX_RegDst = '1' then
            EX_WriteReg <= ID_EX_Rd;
        else
            EX_WriteReg <= ID_EX_Rt;
        end if;
    end process;

    debug_PC         <= PC;
    debug_Instr      <= IF_ID_Instr;
    debug_ALUResult  <= ALUResult_ex;
    debug_Zero       <= ALUZero_ex;
    debug_ALUCtrl    <= ALUCtrl_ex;
    debug_ALU_InA    <= rs_value_for_alu;
    debug_ALU_InB    <= ALU_input_B;
    debug_SignExtImm <= ID_EX_Imm32;
    debug_RegWrite   <= MEM_WB_RegWrite;

end Behavioral;