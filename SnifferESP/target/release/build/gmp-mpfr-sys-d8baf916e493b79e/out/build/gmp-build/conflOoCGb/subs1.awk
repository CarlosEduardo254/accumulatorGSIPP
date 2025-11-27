BEGIN {
S["am__EXEEXT_FALSE"]="#"
S["am__EXEEXT_TRUE"]=""
S["LTLIBOBJS"]=""
S["LIBOBJS"]=""
S["LEXLIB"]=""
S["LEX_OUTPUT_ROOT"]=""
S["LEX"]=""
S["YFLAGS"]=""
S["YACC"]=""
S["LIBREADLINE"]=""
S["WITH_READLINE_01"]=""
S["LIBCURSES"]=""
S["HAVE_STACK_T_01"]=""
S["HAVE_SYS_RESOURCE_H_01"]=""
S["HAVE_SIGSTACK_01"]=""
S["HAVE_SIGALTSTACK_01"]=""
S["HAVE_SIGACTION_01"]=""
S["HAVE_GETTIMEOFDAY_01"]=""
S["HAVE_GETRUSAGE_01"]=""
S["HAVE_CPUTIME_01"]=""
S["HAVE_CLOCK_01"]=""
S["TUNE_SQR_OBJ"]=""
S["gmp_srclinks"]=" mpn/invert_limb_table.asm mpn/fat.c mpn/fat_entry.asm mpn/add.c mpn/add_1.c mpn/sub.c mpn/sub_1.c mpn/cnd_swap.c mpn/neg.c mpn/add_err1_n.c mpn/add"\
"_err2_n.c mpn/add_err3_n.c mpn/sub_err1_n.c mpn/sub_err2_n.c mpn/sub_err3_n.c mpn/diveby3.c mpn/divis.c mpn/divrem.c mpn/divrem_2.asm mpn/fib2_ui.c "\
"mpn/fib2m.c mpn/dump.c mpn/mod_1_3.c mpn/mul.c mpn/mul_fft.c mpn/mul_n.c mpn/sqr.c mpn/nussbaumer_mul.c mpn/mulmid_basecase.c mpn/toom42_mulmid.c mp"\
"n/mulmid_n.c mpn/mulmid.c mpn/random.c mpn/random2.c mpn/pow_1.c mpn/rootrem.c mpn/sqrtrem.c mpn/sizeinbase.c mpn/get_str.c mpn/set_str.c mpn/comput"\
"e_powtab.c mpn/scan0.c mpn/scan1.c mpn/popcount.asm mpn/hamdist.asm mpn/cmp.c mpn/zero_p.c mpn/perfsqr.c mpn/perfpow.c mpn/strongfibo.c mpn/gcd_22.c"\
" mpn/gcd_1.c mpn/gcd.c mpn/gcdext_1.c mpn/gcdext.c mpn/gcd_subdiv_step.c mpn/gcdext_lehmer.c mpn/div_q.c mpn/tdiv_qr.c mpn/jacbase.c mpn/jacobi_2.c "\
"mpn/jacobi.c mpn/get_d.c mpn/matrix22_mul.c mpn/matrix22_mul1_inverse_vector.c mpn/hgcd_matrix.c mpn/hgcd2.c mpn/hgcd_step.c mpn/hgcd_reduce.c mpn/h"\
"gcd.c mpn/hgcd_appr.c mpn/hgcd2_jacobi.c mpn/hgcd_jacobi.c mpn/mullo_n.c mpn/sqrlo.c mpn/sqrlo_basecase.c mpn/toom22_mul.c mpn/toom32_mul.c mpn/toom"\
"42_mul.c mpn/toom52_mul.c mpn/toom62_mul.c mpn/toom33_mul.c mpn/toom43_mul.c mpn/toom53_mul.c mpn/toom54_mul.c mpn/toom63_mul.c mpn/toom44_mul.c mpn"\
"/toom6h_mul.c mpn/toom6_sqr.c mpn/toom8h_mul.c mpn/toom8_sqr.c mpn/toom_couple_handling.c mpn/toom2_sqr.c mpn/toom3_sqr.c mpn/toom4_sqr.c mpn/toom_e"\
"val_dgr3_pm1.c mpn/toom_eval_dgr3_pm2.c mpn/toom_eval_pm1.c mpn/toom_eval_pm2.c mpn/toom_eval_pm2exp.c mpn/toom_eval_pm2rexp.c mpn/toom_interpolate_"\
"5pts.c mpn/toom_interpolate_6pts.c mpn/toom_interpolate_7pts.c mpn/toom_interpolate_8pts.c mpn/toom_interpolate_12pts.c mpn/toom_interpolate_16pts.c"\
" mpn/invertappr.c mpn/invert.c mpn/binvert.c mpn/mulmod_bnm1.c mpn/sqrmod_bnm1.c mpn/mulmod_bknp1.c mpn/div_qr_1.c mpn/div_qr_1n_pi1.c mpn/div_qr_2."\
"c mpn/div_qr_2n_pi1.asm mpn/div_qr_2u_pi1.c mpn/sbpi1_div_q.c mpn/sbpi1_div_qr.c mpn/sbpi1_divappr_q.c mpn/dcpi1_div_q.c mpn/dcpi1_div_qr.c mpn/dcpi"\
"1_divappr_q.c mpn/mu_div_qr.c mpn/mu_divappr_q.c mpn/mu_div_q.c mpn/bdiv_q_1.asm mpn/sbpi1_bdiv_q.c mpn/sbpi1_bdiv_qr.c mpn/sbpi1_bdiv_r.c mpn/dcpi1"\
"_bdiv_q.c mpn/dcpi1_bdiv_qr.c mpn/mu_bdiv_q.c mpn/mu_bdiv_qr.c mpn/bdiv_q.c mpn/bdiv_qr.c mpn/broot.c mpn/brootinv.c mpn/bsqrt.c mpn/bsqrtinv.c mpn/"\
"divexact.c mpn/redc_n.c mpn/powm.c mpn/powlo.c mpn/sec_powm.c mpn/sec_mul.c mpn/sec_sqr.c mpn/sec_div_qr.c mpn/sec_div_r.c mpn/sec_pi1_div_qr.c mpn/"\
"sec_pi1_div_r.c mpn/sec_add_1.c mpn/sec_sub_1.c mpn/sec_invert.c mpn/trialdiv.c mpn/remove.c mpn/and_n.asm mpn/andn_n.asm mpn/nand_n.asm mpn/ior_n.a"\
"sm mpn/iorn_n.asm mpn/nior_n.asm mpn/xor_n.asm mpn/xnor_n.asm mpn/zero.c mpn/sec_tabselect.asm mpn/comb_tables.c mpn/invert_limb.asm mpn/sqr_diag_ad"\
"dlsh1.asm mpn/mul_2.asm mpn/rsblsh1_n.asm mpn/rsh1add_n.asm mpn/rsh1sub_n.asm mpn/rsblsh2_n.asm mpn/addlsh_n.asm mpn/rsblsh_n.asm mpn/add_n_sub_n.c "\
"gmp-mparam.h"
S["mpn_objs_in_libgmp"]=" mpn/x86_64_add_n.lo mpn/x86_64_addmul_1.lo mpn/x86_64_bdiv_dbm1c.lo mpn/x86_64_com.lo mpn/x86_64_cnd_add_n.lo mpn/x86_64_cnd_sub_n.lo mpn/x86_64_co"\
"pyd.lo mpn/x86_64_copyi.lo mpn/x86_64_dive_1.lo mpn/x86_64_divrem_1.lo mpn/x86_64_gcd_11.lo mpn/x86_64_lshift.lo mpn/x86_64_lshiftc.lo mpn/x86_64_mo"\
"d_1_1.lo mpn/x86_64_mod_1_2.lo mpn/x86_64_mod_1_4.lo mpn/x86_64_mod_34lsub1.lo mpn/x86_64_mode1o.lo mpn/x86_64_mul_1.lo mpn/x86_64_rshift.lo mpn/x86"\
"_64_sub_n.lo mpn/x86_64_submul_1.lo mpn/x86_64_addlsh1_n.lo mpn/x86_64_addlsh2_n.lo mpn/x86_64_sublsh1_n.lo mpn/fat_mod_1.lo mpn/fat_mul_basecase.lo"\
" mpn/fat_mullo_basecase.lo mpn/fat_redc_1.lo mpn/fat_redc_2.lo mpn/fat_sqr_basecase.lo mpn/fat_addmul_2.lo mpn/k8_mul_basecase.lo mpn/k8_mullo_basec"\
"ase.lo mpn/k8_redc_1.lo mpn/k8_sqr_basecase.lo mpn/k8_addmul_2.lo mpn/k10_gcd_11.lo mpn/k10_lshift.lo mpn/k10_lshiftc.lo mpn/k10_rshift.lo mpn/bd1_a"\
"dd_n.lo mpn/bd1_addmul_1.lo mpn/bd1_com.lo mpn/bd1_copyd.lo mpn/bd1_copyi.lo mpn/bd1_gcd_11.lo mpn/bd1_mul_1.lo mpn/bd1_mul_basecase.lo mpn/bd1_sub_"\
"n.lo mpn/bd1_submul_1.lo mpn/bd1_addmul_2.lo mpn/bd1_addlsh1_n.lo mpn/bd1_sublsh1_n.lo mpn/bt1_add_n.lo mpn/bt1_addmul_1.lo mpn/bt1_copyd.lo mpn/bt1"\
"_copyi.lo mpn/bt1_gcd_11.lo mpn/bt1_mul_1.lo mpn/bt1_mul_basecase.lo mpn/bt1_redc_1.lo mpn/bt1_sqr_basecase.lo mpn/bt1_sub_n.lo mpn/bt1_submul_1.lo "\
"mpn/bt2_com.lo mpn/bt2_copyd.lo mpn/bt2_copyi.lo mpn/bt2_gcd_11.lo mpn/zen_addmul_1.lo mpn/zen_com.lo mpn/zen_copyd.lo mpn/zen_copyi.lo mpn/zen_gcd_"\
"11.lo mpn/zen_lshift.lo mpn/zen_lshiftc.lo mpn/zen_mul_1.lo mpn/zen_mul_basecase.lo mpn/zen_mullo_basecase.lo mpn/zen_rshift.lo mpn/zen_sqr_basecase"\
".lo mpn/zen_submul_1.lo mpn/zen_addlsh1_n.lo mpn/zen_sublsh1_n.lo mpn/p4_add_n.lo mpn/p4_addmul_1.lo mpn/p4_lshift.lo mpn/p4_lshiftc.lo mpn/p4_mod_3"\
"4lsub1.lo mpn/p4_mul_1.lo mpn/p4_mul_basecase.lo mpn/p4_mullo_basecase.lo mpn/p4_redc_1.lo mpn/p4_rshift.lo mpn/p4_sqr_basecase.lo mpn/p4_sub_n.lo m"\
"pn/p4_submul_1.lo mpn/p4_addmul_2.lo mpn/p4_addlsh1_n.lo mpn/p4_addlsh2_n.lo mpn/p4_sublsh1_n.lo mpn/core2_add_n.lo mpn/core2_addmul_1.lo mpn/core2_"\
"com.lo mpn/core2_copyd.lo mpn/core2_copyi.lo mpn/core2_divrem_1.lo mpn/core2_gcd_11.lo mpn/core2_lshift.lo mpn/core2_lshiftc.lo mpn/core2_mul_baseca"\
"se.lo mpn/core2_mullo_basecase.lo mpn/core2_redc_1.lo mpn/core2_rshift.lo mpn/core2_sqr_basecase.lo mpn/core2_sub_n.lo mpn/core2_submul_1.lo mpn/cor"\
"e2_addlsh1_n.lo mpn/core2_addlsh2_n.lo mpn/core2_sublsh1_n.lo mpn/coreinhm_addmul_1.lo mpn/coreinhm_redc_1.lo mpn/coreinhm_submul_1.lo mpn/coreisbr_"\
"add_n.lo mpn/coreisbr_addmul_1.lo mpn/coreisbr_cnd_add_n.lo mpn/coreisbr_cnd_sub_n.lo mpn/coreisbr_divrem_1.lo mpn/coreisbr_gcd_11.lo mpn/coreisbr_l"\
"shift.lo mpn/coreisbr_lshiftc.lo mpn/coreisbr_mul_1.lo mpn/coreisbr_mul_basecase.lo mpn/coreisbr_mullo_basecase.lo mpn/coreisbr_redc_1.lo mpn/coreis"\
"br_rshift.lo mpn/coreisbr_sqr_basecase.lo mpn/coreisbr_sub_n.lo mpn/coreisbr_submul_1.lo mpn/coreisbr_addmul_2.lo mpn/coreisbr_addlsh1_n.lo mpn/core"\
"isbr_addlsh2_n.lo mpn/coreihwl_add_n.lo mpn/coreihwl_addmul_1.lo mpn/coreihwl_mul_1.lo mpn/coreihwl_mul_basecase.lo mpn/coreihwl_mullo_basecase.lo m"\
"pn/coreihwl_redc_1.lo mpn/coreihwl_sqr_basecase.lo mpn/coreihwl_sub_n.lo mpn/coreihwl_submul_1.lo mpn/coreihwl_addmul_2.lo mpn/coreibwl_addmul_1.lo "\
"mpn/coreibwl_mul_basecase.lo mpn/coreibwl_mullo_basecase.lo mpn/coreibwl_sqr_basecase.lo mpn/atom_add_n.lo mpn/atom_addmul_1.lo mpn/atom_com.lo mpn/"\
"atom_cnd_add_n.lo mpn/atom_cnd_sub_n.lo mpn/atom_copyd.lo mpn/atom_copyi.lo mpn/atom_dive_1.lo mpn/atom_lshift.lo mpn/atom_lshiftc.lo mpn/atom_mul_1"\
".lo mpn/atom_redc_1.lo mpn/atom_rshift.lo mpn/atom_sub_n.lo mpn/atom_submul_1.lo mpn/atom_addmul_2.lo mpn/atom_addlsh1_n.lo mpn/atom_addlsh2_n.lo mp"\
"n/atom_sublsh1_n.lo mpn/silvermont_add_n.lo mpn/silvermont_addmul_1.lo mpn/silvermont_lshift.lo mpn/silvermont_lshiftc.lo mpn/silvermont_mul_1.lo mp"\
"n/silvermont_mul_basecase.lo mpn/silvermont_mullo_basecase.lo mpn/silvermont_rshift.lo mpn/silvermont_sqr_basecase.lo mpn/silvermont_sub_n.lo mpn/si"\
"lvermont_submul_1.lo mpn/silvermont_addlsh1_n.lo mpn/silvermont_addlsh2_n.lo mpn/goldmont_add_n.lo mpn/goldmont_addmul_1.lo mpn/goldmont_mul_1.lo mp"\
"n/goldmont_redc_1.lo mpn/goldmont_sub_n.lo mpn/goldmont_submul_1.lo mpn/nano_copyd.lo mpn/nano_copyi.lo mpn/nano_dive_1.lo mpn/nano_gcd_11.lo mpn/in"\
"vert_limb_table.lo mpn/fat$U.lo mpn/fat_entry.lo mpn/add$U.lo mpn/add_1$U.lo mpn/sub$U.lo mpn/sub_1$U.lo mpn/cnd_swap$U.lo mpn/neg$U.lo mpn/add_err1"\
"_n$U.lo mpn/add_err2_n$U.lo mpn/add_err3_n$U.lo mpn/sub_err1_n$U.lo mpn/sub_err2_n$U.lo mpn/sub_err3_n$U.lo mpn/diveby3$U.lo mpn/divis$U.lo mpn/divr"\
"em$U.lo mpn/divrem_2.lo mpn/fib2_ui$U.lo mpn/fib2m$U.lo mpn/dump$U.lo mpn/mod_1_3$U.lo mpn/mul$U.lo mpn/mul_fft$U.lo mpn/mul_n$U.lo mpn/sqr$U.lo mpn"\
"/nussbaumer_mul$U.lo mpn/mulmid_basecase$U.lo mpn/toom42_mulmid$U.lo mpn/mulmid_n$U.lo mpn/mulmid$U.lo mpn/random$U.lo mpn/random2$U.lo mpn/pow_1$U."\
"lo mpn/rootrem$U.lo mpn/sqrtrem$U.lo mpn/sizeinbase$U.lo mpn/get_str$U.lo mpn/set_str$U.lo mpn/compute_powtab$U.lo mpn/scan0$U.lo mpn/scan1$U.lo mpn"\
"/popcount.lo mpn/hamdist.lo mpn/cmp$U.lo mpn/zero_p$U.lo mpn/perfsqr$U.lo mpn/perfpow$U.lo mpn/strongfibo$U.lo mpn/gcd_22$U.lo mpn/gcd_1$U.lo mpn/gc"\
"d$U.lo mpn/gcdext_1$U.lo mpn/gcdext$U.lo mpn/gcd_subdiv_step$U.lo mpn/gcdext_lehmer$U.lo mpn/div_q$U.lo mpn/tdiv_qr$U.lo mpn/jacbase$U.lo mpn/jacobi"\
"_2$U.lo mpn/jacobi$U.lo mpn/get_d$U.lo mpn/matrix22_mul$U.lo mpn/matrix22_mul1_inverse_vector$U.lo mpn/hgcd_matrix$U.lo mpn/hgcd2$U.lo mpn/hgcd_step"\
"$U.lo mpn/hgcd_reduce$U.lo mpn/hgcd$U.lo mpn/hgcd_appr$U.lo mpn/hgcd2_jacobi$U.lo mpn/hgcd_jacobi$U.lo mpn/mullo_n$U.lo mpn/sqrlo$U.lo mpn/sqrlo_bas"\
"ecase$U.lo mpn/toom22_mul$U.lo mpn/toom32_mul$U.lo mpn/toom42_mul$U.lo mpn/toom52_mul$U.lo mpn/toom62_mul$U.lo mpn/toom33_mul$U.lo mpn/toom43_mul$U."\
"lo mpn/toom53_mul$U.lo mpn/toom54_mul$U.lo mpn/toom63_mul$U.lo mpn/toom44_mul$U.lo mpn/toom6h_mul$U.lo mpn/toom6_sqr$U.lo mpn/toom8h_mul$U.lo mpn/to"\
"om8_sqr$U.lo mpn/toom_couple_handling$U.lo mpn/toom2_sqr$U.lo mpn/toom3_sqr$U.lo mpn/toom4_sqr$U.lo mpn/toom_eval_dgr3_pm1$U.lo mpn/toom_eval_dgr3_p"\
"m2$U.lo mpn/toom_eval_pm1$U.lo mpn/toom_eval_pm2$U.lo mpn/toom_eval_pm2exp$U.lo mpn/toom_eval_pm2rexp$U.lo mpn/toom_interpolate_5pts$U.lo mpn/toom_i"\
"nterpolate_6pts$U.lo mpn/toom_interpolate_7pts$U.lo mpn/toom_interpolate_8pts$U.lo mpn/toom_interpolate_12pts$U.lo mpn/toom_interpolate_16pts$U.lo m"\
"pn/invertappr$U.lo mpn/invert$U.lo mpn/binvert$U.lo mpn/mulmod_bnm1$U.lo mpn/sqrmod_bnm1$U.lo mpn/mulmod_bknp1$U.lo mpn/div_qr_1$U.lo mpn/div_qr_1n_"\
"pi1$U.lo mpn/div_qr_2$U.lo mpn/div_qr_2n_pi1.lo mpn/div_qr_2u_pi1$U.lo mpn/sbpi1_div_q$U.lo mpn/sbpi1_div_qr$U.lo mpn/sbpi1_divappr_q$U.lo mpn/dcpi1"\
"_div_q$U.lo mpn/dcpi1_div_qr$U.lo mpn/dcpi1_divappr_q$U.lo mpn/mu_div_qr$U.lo mpn/mu_divappr_q$U.lo mpn/mu_div_q$U.lo mpn/bdiv_q_1.lo mpn/sbpi1_bdiv"\
"_q$U.lo mpn/sbpi1_bdiv_qr$U.lo mpn/sbpi1_bdiv_r$U.lo mpn/dcpi1_bdiv_q$U.lo mpn/dcpi1_bdiv_qr$U.lo mpn/mu_bdiv_q$U.lo mpn/mu_bdiv_qr$U.lo mpn/bdiv_q$"\
"U.lo mpn/bdiv_qr$U.lo mpn/broot$U.lo mpn/brootinv$U.lo mpn/bsqrt$U.lo mpn/bsqrtinv$U.lo mpn/divexact$U.lo mpn/redc_n$U.lo mpn/powm$U.lo mpn/powlo$U."\
"lo mpn/sec_powm$U.lo mpn/sec_mul$U.lo mpn/sec_sqr$U.lo mpn/sec_div_qr$U.lo mpn/sec_div_r$U.lo mpn/sec_pi1_div_qr$U.lo mpn/sec_pi1_div_r$U.lo mpn/sec"\
"_add_1$U.lo mpn/sec_sub_1$U.lo mpn/sec_invert$U.lo mpn/trialdiv$U.lo mpn/remove$U.lo mpn/and_n.lo mpn/andn_n.lo mpn/nand_n.lo mpn/ior_n.lo mpn/iorn_"\
"n.lo mpn/nior_n.lo mpn/xor_n.lo mpn/xnor_n.lo mpn/zero$U.lo mpn/sec_tabselect.lo mpn/comb_tables$U.lo mpn/invert_limb.lo mpn/sqr_diag_addlsh1.lo mpn"\
"/mul_2.lo mpn/rsblsh1_n.lo mpn/rsh1add_n.lo mpn/rsh1sub_n.lo mpn/rsblsh2_n.lo mpn/addlsh_n.lo mpn/rsblsh_n.lo mpn/add_n_sub_n$U.lo"
S["mpn_objects"]=" x86_64_add_n.lo x86_64_addmul_1.lo x86_64_bdiv_dbm1c.lo x86_64_com.lo x86_64_cnd_add_n.lo x86_64_cnd_sub_n.lo x86_64_copyd.lo x86_64_copyi.lo x86_6"\
"4_dive_1.lo x86_64_divrem_1.lo x86_64_gcd_11.lo x86_64_lshift.lo x86_64_lshiftc.lo x86_64_mod_1_1.lo x86_64_mod_1_2.lo x86_64_mod_1_4.lo x86_64_mod_"\
"34lsub1.lo x86_64_mode1o.lo x86_64_mul_1.lo x86_64_rshift.lo x86_64_sub_n.lo x86_64_submul_1.lo x86_64_addlsh1_n.lo x86_64_addlsh2_n.lo x86_64_subls"\
"h1_n.lo fat_mod_1.lo fat_mul_basecase.lo fat_mullo_basecase.lo fat_redc_1.lo fat_redc_2.lo fat_sqr_basecase.lo fat_addmul_2.lo k8_mul_basecase.lo k8"\
"_mullo_basecase.lo k8_redc_1.lo k8_sqr_basecase.lo k8_addmul_2.lo k10_gcd_11.lo k10_lshift.lo k10_lshiftc.lo k10_rshift.lo bd1_add_n.lo bd1_addmul_1"\
".lo bd1_com.lo bd1_copyd.lo bd1_copyi.lo bd1_gcd_11.lo bd1_mul_1.lo bd1_mul_basecase.lo bd1_sub_n.lo bd1_submul_1.lo bd1_addmul_2.lo bd1_addlsh1_n.l"\
"o bd1_sublsh1_n.lo bt1_add_n.lo bt1_addmul_1.lo bt1_copyd.lo bt1_copyi.lo bt1_gcd_11.lo bt1_mul_1.lo bt1_mul_basecase.lo bt1_redc_1.lo bt1_sqr_basec"\
"ase.lo bt1_sub_n.lo bt1_submul_1.lo bt2_com.lo bt2_copyd.lo bt2_copyi.lo bt2_gcd_11.lo zen_addmul_1.lo zen_com.lo zen_copyd.lo zen_copyi.lo zen_gcd_"\
"11.lo zen_lshift.lo zen_lshiftc.lo zen_mul_1.lo zen_mul_basecase.lo zen_mullo_basecase.lo zen_rshift.lo zen_sqr_basecase.lo zen_submul_1.lo zen_addl"\
"sh1_n.lo zen_sublsh1_n.lo p4_add_n.lo p4_addmul_1.lo p4_lshift.lo p4_lshiftc.lo p4_mod_34lsub1.lo p4_mul_1.lo p4_mul_basecase.lo p4_mullo_basecase.l"\
"o p4_redc_1.lo p4_rshift.lo p4_sqr_basecase.lo p4_sub_n.lo p4_submul_1.lo p4_addmul_2.lo p4_addlsh1_n.lo p4_addlsh2_n.lo p4_sublsh1_n.lo core2_add_n"\
".lo core2_addmul_1.lo core2_com.lo core2_copyd.lo core2_copyi.lo core2_divrem_1.lo core2_gcd_11.lo core2_lshift.lo core2_lshiftc.lo core2_mul_baseca"\
"se.lo core2_mullo_basecase.lo core2_redc_1.lo core2_rshift.lo core2_sqr_basecase.lo core2_sub_n.lo core2_submul_1.lo core2_addlsh1_n.lo core2_addlsh"\
"2_n.lo core2_sublsh1_n.lo coreinhm_addmul_1.lo coreinhm_redc_1.lo coreinhm_submul_1.lo coreisbr_add_n.lo coreisbr_addmul_1.lo coreisbr_cnd_add_n.lo "\
"coreisbr_cnd_sub_n.lo coreisbr_divrem_1.lo coreisbr_gcd_11.lo coreisbr_lshift.lo coreisbr_lshiftc.lo coreisbr_mul_1.lo coreisbr_mul_basecase.lo core"\
"isbr_mullo_basecase.lo coreisbr_redc_1.lo coreisbr_rshift.lo coreisbr_sqr_basecase.lo coreisbr_sub_n.lo coreisbr_submul_1.lo coreisbr_addmul_2.lo co"\
"reisbr_addlsh1_n.lo coreisbr_addlsh2_n.lo coreihwl_add_n.lo coreihwl_addmul_1.lo coreihwl_mul_1.lo coreihwl_mul_basecase.lo coreihwl_mullo_basecase."\
"lo coreihwl_redc_1.lo coreihwl_sqr_basecase.lo coreihwl_sub_n.lo coreihwl_submul_1.lo coreihwl_addmul_2.lo coreibwl_addmul_1.lo coreibwl_mul_basecas"\
"e.lo coreibwl_mullo_basecase.lo coreibwl_sqr_basecase.lo atom_add_n.lo atom_addmul_1.lo atom_com.lo atom_cnd_add_n.lo atom_cnd_sub_n.lo atom_copyd.l"\
"o atom_copyi.lo atom_dive_1.lo atom_lshift.lo atom_lshiftc.lo atom_mul_1.lo atom_redc_1.lo atom_rshift.lo atom_sub_n.lo atom_submul_1.lo atom_addmul"\
"_2.lo atom_addlsh1_n.lo atom_addlsh2_n.lo atom_sublsh1_n.lo silvermont_add_n.lo silvermont_addmul_1.lo silvermont_lshift.lo silvermont_lshiftc.lo si"\
"lvermont_mul_1.lo silvermont_mul_basecase.lo silvermont_mullo_basecase.lo silvermont_rshift.lo silvermont_sqr_basecase.lo silvermont_sub_n.lo silver"\
"mont_submul_1.lo silvermont_addlsh1_n.lo silvermont_addlsh2_n.lo goldmont_add_n.lo goldmont_addmul_1.lo goldmont_mul_1.lo goldmont_redc_1.lo goldmon"\
"t_sub_n.lo goldmont_submul_1.lo nano_copyd.lo nano_copyi.lo nano_dive_1.lo nano_gcd_11.lo invert_limb_table.lo fat$U.lo fat_entry.lo add$U.lo add_1$"\
"U.lo sub$U.lo sub_1$U.lo cnd_swap$U.lo neg$U.lo add_err1_n$U.lo add_err2_n$U.lo add_err3_n$U.lo sub_err1_n$U.lo sub_err2_n$U.lo sub_err3_n$U.lo dive"\
"by3$U.lo divis$U.lo divrem$U.lo divrem_2.lo fib2_ui$U.lo fib2m$U.lo dump$U.lo mod_1_3$U.lo mul$U.lo mul_fft$U.lo mul_n$U.lo sqr$U.lo nussbaumer_mul$"\
"U.lo mulmid_basecase$U.lo toom42_mulmid$U.lo mulmid_n$U.lo mulmid$U.lo random$U.lo random2$U.lo pow_1$U.lo rootrem$U.lo sqrtrem$U.lo sizeinbase$U.lo"\
" get_str$U.lo set_str$U.lo compute_powtab$U.lo scan0$U.lo scan1$U.lo popcount.lo hamdist.lo cmp$U.lo zero_p$U.lo perfsqr$U.lo perfpow$U.lo strongfib"\
"o$U.lo gcd_22$U.lo gcd_1$U.lo gcd$U.lo gcdext_1$U.lo gcdext$U.lo gcd_subdiv_step$U.lo gcdext_lehmer$U.lo div_q$U.lo tdiv_qr$U.lo jacbase$U.lo jacobi"\
"_2$U.lo jacobi$U.lo get_d$U.lo matrix22_mul$U.lo matrix22_mul1_inverse_vector$U.lo hgcd_matrix$U.lo hgcd2$U.lo hgcd_step$U.lo hgcd_reduce$U.lo hgcd$"\
"U.lo hgcd_appr$U.lo hgcd2_jacobi$U.lo hgcd_jacobi$U.lo mullo_n$U.lo sqrlo$U.lo sqrlo_basecase$U.lo toom22_mul$U.lo toom32_mul$U.lo toom42_mul$U.lo t"\
"oom52_mul$U.lo toom62_mul$U.lo toom33_mul$U.lo toom43_mul$U.lo toom53_mul$U.lo toom54_mul$U.lo toom63_mul$U.lo toom44_mul$U.lo toom6h_mul$U.lo toom6"\
"_sqr$U.lo toom8h_mul$U.lo toom8_sqr$U.lo toom_couple_handling$U.lo toom2_sqr$U.lo toom3_sqr$U.lo toom4_sqr$U.lo toom_eval_dgr3_pm1$U.lo toom_eval_dg"\
"r3_pm2$U.lo toom_eval_pm1$U.lo toom_eval_pm2$U.lo toom_eval_pm2exp$U.lo toom_eval_pm2rexp$U.lo toom_interpolate_5pts$U.lo toom_interpolate_6pts$U.lo"\
" toom_interpolate_7pts$U.lo toom_interpolate_8pts$U.lo toom_interpolate_12pts$U.lo toom_interpolate_16pts$U.lo invertappr$U.lo invert$U.lo binvert$U"\
".lo mulmod_bnm1$U.lo sqrmod_bnm1$U.lo mulmod_bknp1$U.lo div_qr_1$U.lo div_qr_1n_pi1$U.lo div_qr_2$U.lo div_qr_2n_pi1.lo div_qr_2u_pi1$U.lo sbpi1_div"\
"_q$U.lo sbpi1_div_qr$U.lo sbpi1_divappr_q$U.lo dcpi1_div_q$U.lo dcpi1_div_qr$U.lo dcpi1_divappr_q$U.lo mu_div_qr$U.lo mu_divappr_q$U.lo mu_div_q$U.l"\
"o bdiv_q_1.lo sbpi1_bdiv_q$U.lo sbpi1_bdiv_qr$U.lo sbpi1_bdiv_r$U.lo dcpi1_bdiv_q$U.lo dcpi1_bdiv_qr$U.lo mu_bdiv_q$U.lo mu_bdiv_qr$U.lo bdiv_q$U.lo"\
" bdiv_qr$U.lo broot$U.lo brootinv$U.lo bsqrt$U.lo bsqrtinv$U.lo divexact$U.lo redc_n$U.lo powm$U.lo powlo$U.lo sec_powm$U.lo sec_mul$U.lo sec_sqr$U."\
"lo sec_div_qr$U.lo sec_div_r$U.lo sec_pi1_div_qr$U.lo sec_pi1_div_r$U.lo sec_add_1$U.lo sec_sub_1$U.lo sec_invert$U.lo trialdiv$U.lo remove$U.lo and"\
"_n.lo andn_n.lo nand_n.lo ior_n.lo iorn_n.lo nior_n.lo xor_n.lo xnor_n.lo zero$U.lo sec_tabselect.lo comb_tables$U.lo invert_limb.lo sqr_diag_addlsh"\
"1.lo mul_2.lo rsblsh1_n.lo rsh1add_n.lo rsh1sub_n.lo rsblsh2_n.lo addlsh_n.lo rsblsh_n.lo add_n_sub_n$U.lo"
S["GMP_LIMB_BITS"]="64"
S["M4"]="m4"
S["TUNE_LIBS"]=""
S["TAL_OBJECT"]="tal-reent.lo"
S["LIBM"]="-lm"
S["ENABLE_STATIC_FALSE"]="#"
S["ENABLE_STATIC_TRUE"]=""
S["LT_SYS_LIBRARY_PATH"]=""
S["OTOOL64"]=""
S["OTOOL"]=""
S["LIPO"]=""
S["NMEDIT"]=""
S["DSYMUTIL"]=""
S["MANIFEST_TOOL"]=":"
S["RANLIB"]="ranlib"
S["ac_ct_AR"]="ar"
S["LN_S"]="cp -pR"
S["LD"]="C:/Strawberry/c/x86_64-w64-mingw32/bin/ld.exe"
S["FGREP"]="/usr/bin/grep -F"
S["SED"]="/usr/bin/sed"
S["LIBTOOL"]="$(SHELL) $(top_builddir)/libtool"
S["LIBGMP_DLL"]="0"
S["OBJDUMP"]="objdump"
S["DLLTOOL"]="dlltool"
S["AS"]="as"
S["NM"]="/usr/bin/nm -B"
S["ac_ct_DUMPBIN"]=""
S["DUMPBIN"]=""
S["AR"]="ar"
S["ASMFLAGS"]=""
S["EGREP"]="/usr/bin/grep -E"
S["GREP"]="/usr/bin/grep"
S["CXXCPP"]=""
S["WANT_CXX_FALSE"]=""
S["WANT_CXX_TRUE"]="#"
S["ac_ct_CXX"]=""
S["CXXFLAGS"]=""
S["CXX"]=""
S["CCAS"]="gcc -c"
S["LIBM_FOR_BUILD"]="-lm"
S["U_FOR_BUILD"]=""
S["EXEEXT_FOR_BUILD"]=".exe"
S["CPP_FOR_BUILD"]="gcc -E"
S["CC_FOR_BUILD"]="gcc"
S["CPP"]="gcc -E"
S["OBJEXT"]="o"
S["EXEEXT"]=".exe"
S["ac_ct_CC"]="gcc"
S["CPPFLAGS"]=""
S["LDFLAGS"]=""
S["CFLAGS"]="-O2 -pedantic -fomit-frame-pointer -m64"
S["CC"]="gcc"
S["DEFN_LONG_LONG_LIMB"]="#define _LONG_LONG_LIMB 1"
S["CALLING_CONVENTIONS_OBJS"]=""
S["SPEED_CYCLECOUNTER_OBJ"]="x86_64.lo"
S["LIBGMPXX_LDFLAGS"]=""
S["LIBGMP_LDFLAGS"]=""
S["GMP_LDFLAGS"]=""
S["HAVE_HOST_CPU_FAMILY_powerpc"]="0"
S["HAVE_HOST_CPU_FAMILY_power"]="0"
S["ABI"]="64"
S["GMP_NAIL_BITS"]="0"
S["MAINT"]="#"
S["MAINTAINER_MODE_FALSE"]=""
S["MAINTAINER_MODE_TRUE"]="#"
S["AM_BACKSLASH"]="\\"
S["AM_DEFAULT_VERBOSITY"]="1"
S["AM_DEFAULT_V"]="$(AM_DEFAULT_VERBOSITY)"
S["AM_V"]="$(V)"
S["am__untar"]="$${TAR-tar} xf -"
S["am__tar"]="$${TAR-tar} chof - \"$$tardir\""
S["AMTAR"]="$${TAR-tar}"
S["am__leading_dot"]="."
S["SET_MAKE"]=""
S["AWK"]="gawk"
S["mkdir_p"]="$(MKDIR_P)"
S["MKDIR_P"]="/usr/bin/mkdir -p"
S["INSTALL_STRIP_PROGRAM"]="$(install_sh) -c -s"
S["STRIP"]="strip"
S["install_sh"]="${SHELL} /c/GSIPP/ImplementacaoAC/SnifferESP/target/release/build/gmp-mpfr-sys-d8baf916e493b79e/out/build/gmp-src/install-sh"
S["MAKEINFO"]="${SHELL} /c/GSIPP/ImplementacaoAC/SnifferESP/target/release/build/gmp-mpfr-sys-d8baf916e493b79e/out/build/gmp-src/missing makeinfo"
S["AUTOHEADER"]="${SHELL} /c/GSIPP/ImplementacaoAC/SnifferESP/target/release/build/gmp-mpfr-sys-d8baf916e493b79e/out/build/gmp-src/missing autoheader"
S["AUTOMAKE"]="${SHELL} /c/GSIPP/ImplementacaoAC/SnifferESP/target/release/build/gmp-mpfr-sys-d8baf916e493b79e/out/build/gmp-src/missing automake-1.15"
S["AUTOCONF"]="${SHELL} /c/GSIPP/ImplementacaoAC/SnifferESP/target/release/build/gmp-mpfr-sys-d8baf916e493b79e/out/build/gmp-src/missing autoconf"
S["ACLOCAL"]="${SHELL} /c/GSIPP/ImplementacaoAC/SnifferESP/target/release/build/gmp-mpfr-sys-d8baf916e493b79e/out/build/gmp-src/missing aclocal-1.15"
S["VERSION"]="6.3.0"
S["PACKAGE"]="gmp"
S["CYGPATH_W"]="cygpath -w"
S["am__isrc"]=" -I$(srcdir)"
S["INSTALL_DATA"]="${INSTALL} -m 644"
S["INSTALL_SCRIPT"]="${INSTALL}"
S["INSTALL_PROGRAM"]="${INSTALL}"
S["host_os"]="msys"
S["host_vendor"]="pc"
S["host_cpu"]="zen2"
S["host"]="zen2-pc-msys"
S["build_os"]="msys"
S["build_vendor"]="pc"
S["build_cpu"]="zen2"
S["build"]="zen2-pc-msys"
S["target_alias"]=""
S["host_alias"]=""
S["build_alias"]=""
S["LIBS"]=""
S["ECHO_T"]=""
S["ECHO_N"]="-n"
S["ECHO_C"]=""
S["DEFS"]="-DHAVE_CONFIG_H"
S["mandir"]="${datarootdir}/man"
S["localedir"]="${datarootdir}/locale"
S["libdir"]="${exec_prefix}/lib"
S["psdir"]="${docdir}"
S["pdfdir"]="${docdir}"
S["dvidir"]="${docdir}"
S["htmldir"]="${docdir}"
S["infodir"]="${datarootdir}/info"
S["docdir"]="${datarootdir}/doc/${PACKAGE_TARNAME}"
S["oldincludedir"]="/usr/include"
S["includedir"]="${prefix}/include"
S["localstatedir"]="${prefix}/var"
S["sharedstatedir"]="${prefix}/com"
S["sysconfdir"]="${prefix}/etc"
S["datadir"]="${datarootdir}"
S["datarootdir"]="${prefix}/share"
S["libexecdir"]="${exec_prefix}/libexec"
S["sbindir"]="${exec_prefix}/sbin"
S["bindir"]="${exec_prefix}/bin"
S["program_transform_name"]="s,x,x,"
S["prefix"]=""
S["exec_prefix"]="${prefix}"
S["PACKAGE_URL"]="http://www.gnu.org/software/gmp/"
S["PACKAGE_BUGREPORT"]="gmp-bugs@gmplib.org (see https://gmplib.org/manual/Reporting-Bugs.html)"
S["PACKAGE_STRING"]="GNU MP 6.3.0"
S["PACKAGE_VERSION"]="6.3.0"
S["PACKAGE_TARNAME"]="gmp"
S["PACKAGE_NAME"]="GNU MP"
S["PATH_SEPARATOR"]=":"
S["SHELL"]="/bin/sh"
  for (key in S) S_is_set[key] = 1
  FS = ""

}
{
  line = $ 0
  nfields = split(line, field, "@")
  substed = 0
  len = length(field[1])
  for (i = 2; i < nfields; i++) {
    key = field[i]
    keylen = length(key)
    if (S_is_set[key]) {
      value = S[key]
      line = substr(line, 1, len) "" value "" substr(line, len + keylen + 3)
      len += length(value) + length(field[++i])
      substed = 1
    } else
      len += 1 + keylen
  }

  print line
}

