CREATE TABLE "authentication_integrity_seals" (
    "model" TEXT NOT NULL,
    "record_id" TEXT NOT NULL,
    "signature" TEXT NOT NULL,
    "updated_at" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "authentication_integrity_seals_pkey" PRIMARY KEY ("model", "record_id")
);
