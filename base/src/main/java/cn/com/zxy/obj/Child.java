package cn.com.zxy.obj;

/**
 * @author infosec
 * @since 2025/11/6
 */
public class Child extends Parent{

    private String child;

    public static void main(String[] args) {
        Child child1 = new Child();
        child1.setParent();
        child1.parentMethod();

        if(child1 instanceof Base) {

        }

    }

}
