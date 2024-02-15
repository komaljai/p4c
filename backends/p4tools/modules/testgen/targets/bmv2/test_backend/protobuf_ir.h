#ifndef BACKENDS_P4TOOLS_MODULES_TESTGEN_TARGETS_BMV2_TEST_BACKEND_PROTOBUF_IR_H_
#define BACKENDS_P4TOOLS_MODULES_TESTGEN_TARGETS_BMV2_TEST_BACKEND_PROTOBUF_IR_H_

#include <cstddef>
#include <string>
#include <utility>

#include <inja/inja.hpp>

#include "lib/cstring.h"

#include "backends/p4tools/modules/testgen/lib/test_spec.h"
#include "backends/p4tools/modules/testgen/targets/bmv2/test_backend/common.h"

namespace P4Tools::P4Testgen::Bmv2 {

struct ProtobufIrTest : public AbstractTest {
 private:
    /// The formatted test. TODO: This should be a Protobuf object.
    std::string formattedTest_;

 public:
    explicit ProtobufIrTest(std::string formattedTest) : formattedTest_(std::move(formattedTest)) {}

    /// @return the formatted test.
    [[nodiscard]] const std::string &getFormattedTest() const { return formattedTest_; }

    DECLARE_TYPEINFO(ProtobufIrTest);
};

/// Extracts information from the @testSpec to emit a Protobuf IR test case.
class ProtobufIr : public Bmv2TestFramework {
 public:
    explicit ProtobufIr(const TestBackendConfiguration &testBackendConfiguration);

    ~ProtobufIr() override = default;
    ProtobufIr(const ProtobufIr &) = default;
    ProtobufIr(ProtobufIr &&) = default;
    ProtobufIr &operator=(const ProtobufIr &) = default;
    ProtobufIr &operator=(ProtobufIr &&) = default;

    void writeTestToFile(const TestSpec *testSpec, cstring selectedBranches, size_t testId,
                         float currentCoverage) override;

    AbstractTestReferenceOrError produceTest(const TestSpec *testSpec, cstring selectedBranches,
                                             size_t testIdx, float currentCoverage) override;

 private:
    [[nodiscard]] inja::json getControlPlaneForTable(
        const TableMatchMap &matches, const std::vector<ActionArg> &args) const override;

    [[nodiscard]] inja::json getSend(const TestSpec *testSpec) const override;

    [[nodiscard]] inja::json getExpectedPacket(const TestSpec *testSpec) const override;

    /// Generates a test case.
    /// @param selectedBranches enumerates the choices the interpreter made for this path.
    /// @param testId specifies the test name.
    /// @param currentCoverage contains statistics  about the current coverage of this test and its
    /// preceding tests.
    inja::json produceTestCase(const TestSpec *testSpec, cstring selectedBranches, size_t testId,
                               float currentCoverage) const;

    /// @returns the inja test case template as a string.
    static std::string getTestCaseTemplate();

    /// Tries to find the @format annotation of a node and, if present, returns the format specified
    /// in this annotation. Returns "hex" by default.
    static std::string getFormatOfNode(const IR::IAnnotated *node);

    /// Converts an IR::Expression into a formatted string value. The format depends on @param type.
    static std::string formatNetworkValue(const std::string &type, const IR::Expression *value);

    /// Fill in @param rulesJson by iterating over @param fieldMatch and creating the appropriate
    /// match key.
    static void createKeyMatch(cstring fieldName, const TableMatch &fieldMatch,
                               inja::json &rulesJson);
};

}  // namespace P4Tools::P4Testgen::Bmv2

#endif /* BACKENDS_P4TOOLS_MODULES_TESTGEN_TARGETS_BMV2_TEST_BACKEND_PROTOBUF_IR_H_ */
