/**
 * Copyright 2013-2023 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#include "srsenb/hdr/enb.h"
#include "srsenb/test/rrc/test_helpers.h"
#include "srsran/common/test_common.h"
#include <cstring>

using namespace asn1::rrc;
using namespace srsenb;

int test_dl_information_transfer_wraps_identity_request()
{
  printf("\n===== TEST: test_dl_information_transfer_wraps_identity_request() =====\n");

  srsran::task_scheduler task_sched;
  srsenb::all_args_t     args;
  rrc_cfg_t              cfg;
  TESTASSERT(test_helpers::parse_default_cfg(&cfg, args) == SRSRAN_SUCCESS);

  enb_bearer_manager              bearers;
  srsenb::rrc                     rrc{&task_sched, bearers};
  mac_dummy                       mac;
  rlc_dummy                       rlc;
  test_dummies::pdcp_mobility_dummy pdcp;
  phy_dummy                       phy;
  test_dummies::s1ap_mobility_dummy s1ap;
  gtpu_dummy                      gtpu;
  TESTASSERT(rrc.init(cfg, &phy, &mac, &rlc, &pdcp, &s1ap, &gtpu) == SRSRAN_SUCCESS);

  const uint16_t            rnti = 0x46;
  sched_interface::ue_cfg_t ue_cfg{};
  ue_cfg.supported_cc_list.resize(1);
  ue_cfg.supported_cc_list[0].active     = true;
  ue_cfg.supported_cc_list[0].enb_cc_idx = 0;
  TESTASSERT(rrc.add_user(rnti, ue_cfg) == SRSRAN_SUCCESS);

  // Plain NAS Identity Request for IMSI, TS 24.301 section 8.2.18.
  const uint8_t standard_nas_identity_req[] = {0x07, 0x55, 0x01};
  auto          nas_sdu     = srsran::make_byte_buffer();
  TESTASSERT(nas_sdu != nullptr);
  memcpy(nas_sdu->msg, standard_nas_identity_req, sizeof(standard_nas_identity_req));
  nas_sdu->N_bytes = sizeof(standard_nas_identity_req);

  rrc.write_dl_info(rnti, std::move(nas_sdu));

  TESTASSERT(pdcp.last_sdu.rnti == rnti);
  TESTASSERT(pdcp.last_sdu.lcid == srb_to_lcid(lte_srb::srb1));
  TESTASSERT(pdcp.last_sdu.sdu != nullptr);

  dl_dcch_msg_s dl_dcch_msg;
  TESTASSERT(test_helpers::unpack_asn1(dl_dcch_msg, srsran::make_span(pdcp.last_sdu.sdu)));
  TESTASSERT(dl_dcch_msg.msg.type().value == dl_dcch_msg_type_c::types_opts::c1);
  TESTASSERT(dl_dcch_msg.msg.c1().type().value == dl_dcch_msg_type_c::c1_c_::types_opts::dl_info_transfer);

  const auto& dl_info_r8 = dl_dcch_msg.msg.c1().dl_info_transfer().crit_exts.c1().dl_info_transfer_r8();
  TESTASSERT(dl_info_r8.ded_info_type.type().value == dl_info_transfer_r8_ies_s::ded_info_type_c_::types_opts::ded_info_nas);

  const auto& wrapped_nas = dl_info_r8.ded_info_type.ded_info_nas();
  TESTASSERT(wrapped_nas.size() == sizeof(standard_nas_identity_req));
  TESTASSERT(memcmp(wrapped_nas.data(), standard_nas_identity_req, sizeof(standard_nas_identity_req)) == 0);

  return SRSRAN_SUCCESS;
}

int main(int argc, char** argv)
{
  srslog::init();

  if (argc < 3) {
    argparse::usage(argv[0]);
    return SRSRAN_ERROR;
  }
  argparse::parse_args(argc, argv);

  auto& logger = srslog::fetch_basic_logger("RRC", false);
  logger.set_level(srslog::basic_levels::none);

  TESTASSERT(test_dl_information_transfer_wraps_identity_request() == SRSRAN_SUCCESS);

  printf("\nSuccess\n");
  return SRSRAN_SUCCESS;
}
