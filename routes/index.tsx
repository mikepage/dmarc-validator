import { Head } from "fresh/runtime";
import { define } from "../utils.ts";
import DmarcValidator from "../islands/DmarcValidator.tsx";

export default define.page(function Home() {
  return (
    <div class="min-h-screen bg-[#fafafa]">
      <Head>
        <title>DMARC Validator</title>
      </Head>
      <div class="px-6 md:px-12 py-8">
        <div class="max-w-4xl mx-auto">
          <h1 class="text-2xl font-normal text-[#111] tracking-tight mb-2">
            DMARC Validator
          </h1>
          <p class="text-[#666] text-sm mb-8">
            Check the DMARC record for any domain. DMARC (Domain-based Message
            Authentication, Reporting, and Conformance) helps protect against
            email spoofing.
          </p>
          <DmarcValidator />
        </div>
      </div>
    </div>
  );
});
