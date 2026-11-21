CREATE TABLE "financial_integrity_seals" (
  "kind" TEXT NOT NULL,
  "record_id" TEXT NOT NULL,
  "signature" TEXT NOT NULL,
  "updated_at" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "financial_integrity_seals_pkey" PRIMARY KEY ("kind", "record_id")
);
