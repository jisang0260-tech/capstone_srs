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
#include "srsran/asn1/liblte_mme.h"
#include "srsran/common/test_common.h"
#include <algorithm>
#include <cstring>

using namespace asn1::rrc;
using namespace srsenb;

namespace {

class s1ap_capture_dummy : public test_dummies::s1ap_mobility_dummy
{
public:
  void write_pdu(uint16_t rnti, srsran::unique_byte_buffer_t pdu) override
  {
    last_rnti = rnti;
    last_pdu  = std::move(pdu);
  }

  uint16_t                     last_rnti = SRSRAN_INVALID_RNTI;
  srsran::unique_byte_buffer_t last_pdu;
};

uint64_t digits_to_uint64(const uint8_t (&digits)[15])
{
  uint64_t value = 0;
  for (uint32_t i = 0; i < 15; ++i) {
    value = value * 10 + digits[i];
  }
  return value;
}

bool has_expected_pcch_paging_for_imsi(srsenb::rrc& rrc, const uint8_t (&imsi_digits)[15])
{
  for (uint32_t tti = 0; tti < 10240; ++tti) {
    uint32_t payload_len = 0;
    if (not rrc.is_paging_opportunity(tti, &payload_len)) {
      continue;
    }

    uint8_t pcch_payload[1024] = {};
    TESTASSERT(payload_len <= sizeof(pcch_payload));
    rrc.read_pdu_pcch(tti, pcch_payload, sizeof(pcch_payload));

    pcch_msg_s     pcch_msg;
    asn1::cbit_ref bref(pcch_payload, payload_len);
    TESTASSERT(pcch_msg.unpack(bref) == asn1::SRSASN_SUCCESS);
    TESTASSERT(pcch_msg.msg.type().value == pcch_msg_type_c::types_opts::c1);

    const auto& paging = pcch_msg.msg.c1().paging();
    TESTASSERT(paging.paging_record_list_present);
    TESTASSERT(paging.paging_record_list.size() == 1);

    const auto& paging_record = paging.paging_record_list[0];
    TESTASSERT(paging_record.cn_domain.value == paging_record_s::cn_domain_opts::ps);
    TESTASSERT(paging_record.ue_id.type().value == paging_ue_id_c::types_opts::imsi);
    TESTASSERT(paging_record.ue_id.imsi().size() == 15);
    TESTASSERT(std::equal(paging_record.ue_id.imsi().begin(), paging_record.ue_id.imsi().end(), imsi_digits));
    return true;
  }

  return false;
}

srsran::unique_byte_buffer_t pack_identity_response_nas(const uint8_t (&imsi_digits)[15])
{
  LIBLTE_MME_ID_RESPONSE_MSG_STRUCT id_resp = {};
  id_resp.mobile_id.type_of_id              = LIBLTE_MME_MOBILE_ID_TYPE_IMSI;
  memcpy(id_resp.mobile_id.imsi, imsi_digits, sizeof(imsi_digits));

  auto nas_pdu = srsran::make_byte_buffer();
  TESTASSERT(nas_pdu != nullptr);
  TESTASSERT(liblte_mme_pack_identity_response_msg(&id_resp,
                                                   LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS,
                                                   0,
                                                   reinterpret_cast<LIBLTE_BYTE_MSG_STRUCT*>(nas_pdu.get())) ==
             LIBLTE_SUCCESS);
  return nas_pdu;
}

srsran::unique_byte_buffer_t pack_ul_info_transfer(const srsran::byte_buffer_t& nas_pdu)
{
  ul_dcch_msg_s ul_dcch_msg;
  auto&         ul_info_r8 = ul_dcch_msg.msg.set_c1().set_ul_info_transfer().crit_exts.set_c1().set_ul_info_transfer_r8();

  auto& ded_info_nas = ul_info_r8.ded_info_type.set_ded_info_nas();
  ded_info_nas.resize(nas_pdu.N_bytes);
  memcpy(ded_info_nas.data(), nas_pdu.msg, nas_pdu.N_bytes);

  auto rrc_pdu = srsran::make_byte_buffer();
  TESTASSERT(rrc_pdu != nullptr);
  asn1::bit_ref bref(rrc_pdu->msg, rrc_pdu->get_tailroom());
  TESTASSERT(ul_dcch_msg.pack(bref) == asn1::SRSASN_SUCCESS);
  rrc_pdu->N_bytes = static_cast<uint32_t>(bref.distance_bytes());
  return rrc_pdu;
}

int add_test_user(srsenb::rrc& rrc, uint16_t rnti)
{
  sched_interface::ue_cfg_t ue_cfg{};
  ue_cfg.supported_cc_list.resize(1);
  ue_cfg.supported_cc_list[0].active     = true;
  ue_cfg.supported_cc_list[0].enb_cc_idx = 0;
  return rrc.add_user(rnti, ue_cfg);
}

int test_autonomous_identity_response_paging()
{
  printf("\n===== TEST: test_autonomous_identity_response_paging() =====\n");

  srsran::task_scheduler task_sched;
  srsenb::all_args_t     args;
  rrc_cfg_t              cfg;
  TESTASSERT(test_helpers::parse_default_cfg(&cfg, args) == SRSRAN_SUCCESS);

  enb_bearer_manager                bearers;
  srsenb::rrc                       rrc{&task_sched, bearers};
  mac_dummy                         mac;
  rlc_dummy                         rlc;
  test_dummies::pdcp_mobility_dummy pdcp;
  phy_dummy                         phy;
  s1ap_capture_dummy                s1ap;
  gtpu_dummy                        gtpu;
  TESTASSERT(rrc.init(cfg, &phy, &mac, &rlc, &pdcp, &s1ap, &gtpu) == SRSRAN_SUCCESS);

  const uint16_t rnti            = 0x47;
  const uint8_t  imsi_digits[15] = {0, 0, 1, 0, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  auto           nas_pdu         = pack_identity_response_nas(imsi_digits);
  const uint32_t nas_len         = nas_pdu->N_bytes;
  uint8_t        nas_copy[LIBLTE_MAX_MSG_SIZE_BYTES] = {};
  TESTASSERT(nas_len <= sizeof(nas_copy));
  memcpy(nas_copy, nas_pdu->msg, nas_len);

  TESTASSERT(add_test_user(rrc, rnti) == SRSRAN_SUCCESS);
  rrc.write_pdu(rnti, srb_to_lcid(lte_srb::srb1), pack_ul_info_transfer(*nas_pdu));
  rrc.tti_clock();

  TESTASSERT(s1ap.last_rnti == rnti);
  TESTASSERT(s1ap.last_pdu != nullptr);
  TESTASSERT(s1ap.last_pdu->N_bytes == nas_len);
  TESTASSERT(memcmp(s1ap.last_pdu->msg, nas_copy, nas_len) == 0);

  uint64_t captured_imsi = 0;
  TESTASSERT(rrc.get_autonomous_identity_response_imsi(rnti, captured_imsi));
  TESTASSERT(captured_imsi == digits_to_uint64(imsi_digits));
  TESTASSERT(has_expected_pcch_paging_for_imsi(rrc, imsi_digits));

  return SRSRAN_SUCCESS;
}

} // namespace

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

  TESTASSERT(test_autonomous_identity_response_paging() == SRSRAN_SUCCESS);

  printf("\nSuccess\n");
  return SRSRAN_SUCCESS;
}
