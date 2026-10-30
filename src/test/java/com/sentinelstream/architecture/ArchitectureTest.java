package com.sentinelstream.architecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.library.dependencies.SlicesRuleDefinition.slices;

class ArchitectureTest {

    static final JavaClasses CLASSES = new ClassFileImporter().withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("com.sentinelstream");

    @Test
    void domainCodeIsPlainJava() {
        noClasses().that().resideInAPackage("..domain..")
                .should().dependOnClassesThat().resideInAnyPackage("org.springframework..", "org.apache.kafka..", "jakarta.persistence..",
                        "software.amazon..", "io.lettuce..", "..adapter..", "..application..")
                .check(CLASSES);
    }

    @Test
    void applicationCodeDoesNotReachIntoAdapters() {
        noClasses().that().resideInAPackage("..application..").should().dependOnClassesThat().resideInAPackage("..adapter..")
                .check(CLASSES);
    }

    @Test
    void adaptersOfOneModuleDoNotUseAnotherModulesAdapters() {
        slices().matching("com.sentinelstream.(*).adapter..").should().notDependOnEachOther().check(CLASSES);
    }
}
